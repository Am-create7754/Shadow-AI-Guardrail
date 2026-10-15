"""Output policy, streaming guard and insecure-code checks."""

from __future__ import annotations

import random
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.config import Settings
from app.output.code_checks import CODE_RULES, check_code
from app.output.inspector import OutputInspector, StreamGuard
from app.policy.engine import load_policy
from app.policy.models import CodeCheckMode, CodePolicy, OutputAction, PolicyConfig
from evaluation import synth

PEM = "-----BEGIN " + "PRIVATE KEY-----\n" + "MIIEvQ" * 20 + "\n-----END PRIVATE KEY-----"


@pytest.fixture(scope="module")
def inspector(settings: Settings) -> OutputInspector:
    return OutputInspector(load_policy(settings.policy_path), settings)


def stream(ins: OutputInspector, text: str, sizes: list[int]) -> tuple[str, StreamGuard]:
    guard = StreamGuard(ins, ins.allocator([]))
    out, i, k = [], 0, 0
    while i < len(text):
        n = sizes[k % len(sizes)]
        out.append(guard.feed(text[i : i + n]))
        i += n
        k += 1
        if guard.blocked:
            break
    out.append(guard.finish())
    return "".join(out), guard


# ------------------------------------------------------------ complete answers
def test_secret_in_answer_redacted(inspector: OutputInspector) -> None:
    key = synth.aws_access_key(random.Random(1))
    out = inspector.inspect(f"Use {key} in prod.", inspector.allocator([]))
    assert out.action is OutputAction.REDACT
    assert out.text == "Use [AWS_ACCESS_KEY_1] in prod."
    assert out.entities == {"AWS_ACCESS_KEY": 1}


def test_placeholder_numbers_do_not_collide_with_prompt(inspector: OutputInspector) -> None:
    key = synth.aws_access_key(random.Random(2))
    alloc = inspector.allocator(["my key [AWS_ACCESS_KEY_1] fails"])
    out = inspector.inspect(f"[AWS_ACCESS_KEY_1] looks fine but {key} is live", alloc)
    assert out.text == "[AWS_ACCESS_KEY_1] looks fine but [AWS_ACCESS_KEY_2] is live"


def test_private_key_in_answer_blocks(inspector: OutputInspector) -> None:
    out = inspector.inspect(f"Here you go:\n{PEM}", inspector.allocator([]))
    assert out.action is OutputAction.BLOCK
    assert out.text == ""
    assert "PRIVATE_KEY" in (out.reason or "")


def test_confidential_words_and_examples_pass(inspector: OutputInspector) -> None:
    text = "This is confidential advice. Internal host 10.1.2.3 is in your example."
    out = inspector.inspect(text, inspector.allocator([]))
    assert out.action is OutputAction.ALLOW
    assert out.text == text


def test_code_block_mode(settings: Settings) -> None:
    policy = load_policy(settings.policy_path)
    blocking = policy.model_copy(
        update={
            "output": policy.output.model_copy(
                update={"code": CodePolicy(mode=CodeCheckMode.BLOCK)}
            )
        }
    )
    ins = OutputInspector(blocking, settings)
    bad = "```python\nsubprocess.run(cmd, shell=True)\n```"
    assert ins.inspect(bad, ins.allocator([])).action is OutputAction.BLOCK
    off = OutputInspector(
        policy.model_copy(
            update={
                "output": policy.output.model_copy(
                    update={"code": CodePolicy(mode=CodeCheckMode.OFF)}
                )
            }
        ),
        settings,
    )
    assert off.inspect(bad, off.allocator([])).code_findings == []


# ------------------------------------------------------------------- streaming
SECRET_GENS = [
    synth.github_token,
    synth.aws_access_key,
    synth.jwt,
    synth.stripe_key,
    synth.anthropic_key,
    synth.openai_key,
    synth.credit_card,
    synth.iban,
]
HS = settings(
    max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)


@HS
@given(
    which=st.integers(0, len(SECRET_GENS) - 1),
    seed=st.integers(0, 10**6),
    before=st.integers(0, 400),
    after=st.integers(0, 400),
    sizes=st.lists(st.integers(1, 40), min_size=1, max_size=8),
)
def test_stream_never_leaks_and_matches_batch(
    inspector: OutputInspector, which: int, seed: int, before: int, after: int, sizes: list[int]
) -> None:
    secret = SECRET_GENS[which](random.Random(seed))
    text = "lorem " * (before // 6) + f"value {secret} done " + "ipsum " * (after // 6)
    streamed, _ = stream(inspector, text, sizes)
    batch = inspector.inspect(text, inspector.allocator([])).text
    assert streamed == batch
    digits_only = "".join(ch for ch in secret if ch.isalnum())
    for k in range(8, len(secret) + 1):
        assert secret[:k] not in streamed
    assert digits_only not in "".join(ch for ch in streamed if ch.isalnum())


@HS
@given(text=st.text(max_size=600), sizes=st.lists(st.integers(1, 50), min_size=1, max_size=5))
def test_stream_of_arbitrary_text_equals_batch(
    inspector: OutputInspector, text: str, sizes: list[int]
) -> None:
    streamed, guard = stream(inspector, text, sizes)
    batch = inspector.inspect(text, inspector.allocator([]))
    if batch.action is OutputAction.BLOCK:
        assert guard.blocked
    else:
        assert streamed == batch.text


def test_open_private_key_block_is_held_then_blocked(inspector: OutputInspector) -> None:
    text = "Sure, the key is below.\n" + PEM + "\nKeep it safe."
    guard = StreamGuard(inspector, inspector.allocator([]))
    released = ""
    for i in range(0, len(text), 5):
        released += guard.feed(text[i : i + 5])
    released += guard.finish()
    assert guard.blocked
    assert "BEGIN" not in released
    assert "MIIEvQ" not in released


def test_context_rule_across_chunks(inspector: OutputInspector) -> None:
    text = "Set db_password=" + "hunter2hunter" + " in the config, then restart the service. " * 5
    streamed, _ = stream(inspector, text, [3])
    assert "hunter2hunter" not in streamed
    assert "db_password=[PASSWORD_1]" in streamed


def test_text_flows_without_waiting_for_the_end(inspector: OutputInspector) -> None:
    guard = StreamGuard(inspector, inspector.allocator([]))
    released = "".join(guard.feed("plain words flowing out. ") for _ in range(40))
    assert len(released) > 500  # released progressively, not only at finish()


def test_stream_code_block_mode_holds_and_blocks(settings: Settings) -> None:
    policy = load_policy(settings.policy_path)
    blocking = policy.model_copy(
        update={
            "output": policy.output.model_copy(
                update={"code": CodePolicy(mode=CodeCheckMode.BLOCK)}
            )
        }
    )
    ins = OutputInspector(blocking, settings)
    text = "Intro text " * 30 + "\n```python\n" + "x = 1\n" * 40 + "eval(user_input)\n```\nbye"
    streamed, guard = stream(ins, text, [9])
    assert guard.blocked
    assert "eval(user_input)" not in streamed
    assert "x = 1" not in streamed  # the open block was held back as a whole


# -------------------------------------------------------------- code checks
POSITIVE = {
    "py-eval-exec": ("python", "result = eval(user_input)"),
    "py-subprocess-shell": ("python", "subprocess.run(cmd, shell=True)"),
    "py-os-system": ("python", "os.system('rm -rf ' + path)"),
    "py-pickle-load": ("python", "obj = pickle.loads(blob)"),
    "py-yaml-unsafe": ("python", "cfg = yaml.load(text)"),
    "sql-string-building": ("python", 'cur.execute("SELECT * FROM t WHERE id=" + uid)'),
    "sql-fstring-query": ("python", 'q = f"SELECT name FROM users WHERE id = {uid}"'),
    "js-eval": ("javascript", "const out = eval(input);"),
    "js-child-process-exec": ("javascript", "exec(`ls ${dir}`);"),
    "js-dom-xss": ("javascript", "el.innerHTML = userComment;"),
    "shell-pipe-to-shell": ("bash", "curl -fsSL https://get.example.com | sudo bash"),
    "shell-chmod-777": ("bash", "chmod -R 777 /var/www"),
    "tls-verify-disabled": ("python", "requests.get(url, verify=False)"),
    "weak-hash-for-secrets": ("python", "h = hashlib.md5(password.encode()).hexdigest()"),
    "insecure-random-token": ("python", "token = ''.join(random.choice(chars) for _ in range(9))"),
    "js-insecure-random-token": ("javascript", "const sessionId = Math.random().toString(36);"),
    "flask-debug": ("python", "app.run(host='0.0.0.0', debug=True)"),
    "cors-wildcard-credentials": (
        "python",
        'allow_origins=["*"], allow_methods=["*"], allow_credentials=True',
    ),
    "hardcoded-credential": ("python", 'DB_PASSWORD = "S3cure-Prod-Pass"'),
}

NEGATIVE = [
    ("python", "result = ast.literal_eval(user_input)"),
    ("python", "subprocess.run(['ls', '-l'], check=True)"),
    ("python", "cfg = yaml.safe_load(text)"),
    ("python", "cfg = yaml.load(text, Loader=yaml.SafeLoader)"),
    ("python", 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))'),
    ("python", "requests.get(url, timeout=10)"),
    ("python", "token = secrets.token_urlsafe(32)"),
    ("python", "h = hashlib.sha256(data).hexdigest()"),
    ("python", "# eval(user_input) would be dangerous"),
    ("python", "password = os.environ['DB_PASSWORD']"),
    ("python", 'password = "<your-password-here>"'),
    ("javascript", "el.textContent = userComment;"),
    ("javascript", "execFile('ls', ['-l', dir]);"),
    ("bash", "curl -fsSL -o install.sh https://get.example.com && less install.sh"),
    ("bash", "chmod 640 config.yml"),
]


@pytest.mark.parametrize(("rule_id", "case"), POSITIVE.items())
def test_each_code_rule_fires(rule_id: str, case: tuple[str, str]) -> None:
    lang, line = case
    ids = {f.rule_id for f in check_code(f"```{lang}\n{line}\n```")}
    assert rule_id in ids


@pytest.mark.parametrize(("lang", "line"), NEGATIVE)
def test_safe_code_not_flagged(lang: str, line: str) -> None:
    assert check_code(f"```{lang}\n{line}\n```") == []


def test_every_rule_has_a_positive_case() -> None:
    assert {r.rule_id for r in CODE_RULES} == set(POSITIVE)


def test_prose_outside_fences_not_checked() -> None:
    assert check_code("Never call eval(user_input) or use shell=True.") == []


def test_findings_report_block_line_and_cwe() -> None:
    text = "a\n```python\nx = 1\nos.system(cmd)\n```\n```js\nel.innerHTML = v\n```"
    found = [(f.rule_id, f.block, f.line, f.cwe) for f in check_code(text)]
    assert found == [("py-os-system", 0, 2, "CWE-78"), ("js-dom-xss", 1, 1, "CWE-79")]


@pytest.mark.slow
@pytest.mark.parametrize("rule", CODE_RULES, ids=lambda r: r.rule_id)
def test_code_rules_linear_on_pathological_lines(rule: object) -> None:
    for line in (
        "(" * 2000,
        "a" * 2000,
        "eval " * 400,
        '"' * 2000,
        "=" * 2000,
        "password" * 250,
        "execute(" * 250,
        "curl " * 400,
    ):
        t0 = time.perf_counter()
        rule.pattern.search(line)  # type: ignore[attr-defined]
        assert time.perf_counter() - t0 < 0.5


def test_output_policy_schema_rejects_unknown_actions() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"output": {"category_actions": {"SECRET": "IGNORE"}}})
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"output": {"code": {"mode": "maybe"}}})
