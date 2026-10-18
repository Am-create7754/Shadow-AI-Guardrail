# Deploying the extension with enterprise policy

Without policy, a user can switch the extension off, remove it, open an
Incognito window (where extensions do not run by default) or use an AI site it
does not cover. Managed-browser policy closes those gaps on company devices.

What the generated policy does:

| Policy | Effect |
|---|---|
| `ExtensionInstallForcelist` | Installs the extension on every managed browser; users cannot disable or remove it |
| `3rdparty/extensions/<id>/policy` | Pins `gatewayUrl`, `failMode`, `uploadPolicy` and `enabled=true` (read by the extension via `chrome.storage.managed`; the options page shows them as locked) |
| `URLBlocklist` | Blocks AI sites the extension does not cover (`deploy/ai-domains.json` → `block_in_browser`) |
| `IncognitoModeAvailability = 1` (Chrome), `InPrivateModeAvailability = 1` (Edge) | Disables private windows, where the extension would not run |
| `BrowserGuestModeEnabled = false` | Disables Guest mode, which has no extensions |

## Steps (Windows PowerShell)

1. **Build an organisation package** that already has access to the gateway:

   ```powershell
   cd extension
   npm ci
   node build.mjs --gateway=https://guardrail.example.com
   ```

2. **Pack it** with a signing key. The `.pem` private key fixes the extension ID:
   keep it in your secret store, **never in the repository** (`*.pem` is ignored).

   ```powershell
   & "C:\Program Files\Google\Chrome\Application\chrome.exe" --pack-extension="$PWD\dist"
   # -> dist.crx and dist.pem; the extension ID is shown on chrome://extensions
   #    after dragging dist.crx in, or computed from the key
   ```

   Alternatively publish it as an unlisted / private item in the Chrome Web Store
   or Microsoft Edge Add-ons; the store then hosts it and provides the ID and
   update URL.

3. **Host** `dist.crx` and `updates.xml` on an HTTPS server, then **generate the policy**:

   ```powershell
   .\deploy\chrome-policy\New-GuardrailPolicy.ps1 `
       -ExtensionId <32-letter id> `
       -UpdateUrl https://guardrail.example.com/extension/updates.xml `
       -CrxUrl https://guardrail.example.com/extension/guardrail.crx `
       -GatewayUrl https://guardrail.example.com `
       -OutDir .\deploy\chrome-policy\out
   ```

   Output: `guardrail-chrome.reg`, `guardrail-edge.reg`, `guardrail-policy.json`
   (Linux: `/etc/opt/chrome/policies/managed/`; macOS: same keys in a
   configuration profile), `ai-blocklist.txt` (for the network layer) and
   `updates.xml`.

4. **Deploy** through Group Policy, Intune (OMA-URI / settings catalog) or the
   Google Admin console. For a test machine, double-click the `.reg` file and open
   `chrome://policy` to confirm the values, then `chrome://extensions` to see the
   extension marked "Installed by your administrator".

## Limits

Policy protects **managed browsers on managed devices**. Personal devices,
other browsers (block them with application control such as AppLocker or Intune)
and AI sites missing from the lists need the network layer described in
`docs/SECURITY-ARCHITECTURE.md`. Review `deploy/ai-domains.json` regularly; new AI
services appear constantly.
