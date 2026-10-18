<#
.SYNOPSIS
  Generates browser and network policy files for the Shadow AI Guardrail extension.

.DESCRIPTION
  Writes, into -OutDir:
    guardrail-chrome.reg   Windows policy for Google Chrome (import with regedit, or
                           translate into a Group Policy / Intune configuration)
    guardrail-edge.reg     the same for Microsoft Edge
    guardrail-policy.json  Chrome policy file for Linux (/etc/opt/chrome/policies/managed/)
                           and the structure for macOS configuration profiles
    ai-blocklist.txt       domains for a DNS filter / web proxy (network layer)

  The policies:
    * force-install the extension (users cannot disable or remove it),
    * pin its settings (gateway, fail mode, upload policy, enabled),
    * block AI sites the extension does not cover (URLBlocklist),
    * disable Incognito and Guest mode, where the extension would not run.

  Nothing is applied to this machine; the files are reviewed and deployed by IT.

.EXAMPLE
  .\New-GuardrailPolicy.ps1 -ExtensionId abcdefghijklmnopabcdefghijklmnop `
      -UpdateUrl https://guardrail.example.com/extension/updates.xml `
      -GatewayUrl https://guardrail.example.com -OutDir .\out
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[a-p]{32}$')] [string] $ExtensionId,
    [Parameter(Mandatory)] [ValidatePattern('^https://')] [string] $UpdateUrl,
    [Parameter(Mandatory)] [string] $GatewayUrl,
    [ValidateSet('block', 'allow')] [string] $FailMode = 'block',
    [ValidateSet('block', 'warn')] [string] $UploadPolicy = 'block',
    # Where the packed .crx is served; when given, updates.xml is generated too.
    [string] $CrxUrl,
    [string] $DomainsFile = (Join-Path $PSScriptRoot '..\ai-domains.json'),
    [string] $OutDir = (Join-Path $PSScriptRoot 'out')
)
$ErrorActionPreference = 'Stop'

# Same rule as the extension: HTTPS, or plain HTTP only for this machine.
$gw = [Uri] $GatewayUrl
$loopback = @('127.0.0.1', 'localhost', '[::1]')
if (-not ($gw.Scheme -eq 'https' -or ($gw.Scheme -eq 'http' -and $loopback -contains $gw.Host))) {
    throw 'GatewayUrl must use https:// (http only for 127.0.0.1 / localhost)'
}
if ($gw.AbsolutePath -ne '/' -or $gw.Query -or $gw.UserInfo) { throw 'GatewayUrl must be an origin only' }
$origin = $gw.GetLeftPart([UriPartial]::Authority)

# URLs end up in .reg, JSON and XML files: absolute https URLs without control
# characters, quotes or ';' (the force-list separator) only.
function Assert-SafeUrl([string] $name, [string] $value) {
    $u = $null
    if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref] $u) -or $u.Scheme -ne 'https' -or
        $value -match '[\x00-\x1f\x7f";\s]') {
        throw "$name must be an absolute https:// URL without spaces, quotes, ';' or control characters"
    }
}
Assert-SafeUrl 'UpdateUrl' $UpdateUrl
if ($CrxUrl) { Assert-SafeUrl 'CrxUrl' $CrxUrl }

$domains = Get-Content -Raw -Encoding UTF8 $DomainsFile | ConvertFrom-Json
$blocklist = @($domains.block_in_browser)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Escape-Reg([string] $s) { $s.Replace('\', '\\').Replace('"', '\"') }

function New-RegFile([string] $root, [string] $privateModePolicy) {
    $lines = @('Windows Registry Editor Version 5.00', '')
    $lines += "[$root\ExtensionInstallForcelist]"
    $lines += ('"1"="{0};{1}"' -f $ExtensionId, (Escape-Reg $UpdateUrl))
    $lines += ''
    $lines += "[$root\URLBlocklist]"
    for ($i = 0; $i -lt $blocklist.Count; $i++) { $lines += ('"{0}"="{1}"' -f ($i + 1), (Escape-Reg $blocklist[$i])) }
    $lines += ''
    $lines += "[$root]"
    $lines += ('"{0}"=dword:00000001' -f $privateModePolicy)  # 1 = private browsing disabled
    $lines += '"BrowserGuestModeEnabled"=dword:00000000'
    $lines += ''
    # Settings read by the extension through chrome.storage.managed.
    $lines += "[$root\3rdparty\extensions\$ExtensionId\policy]"
    $lines += ('"gatewayUrl"="{0}"' -f (Escape-Reg $origin))
    $lines += ('"failMode"="{0}"' -f $FailMode)
    $lines += ('"uploadPolicy"="{0}"' -f $UploadPolicy)
    $lines += '"enabled"=dword:00000001'
    $lines += ''
    # .reg files are UTF-16 LE with BOM.
    return ($lines -join "`r`n")
}

[IO.File]::WriteAllText((Join-Path $OutDir 'guardrail-chrome.reg'), (New-RegFile 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome' 'IncognitoModeAvailability'), [Text.Encoding]::Unicode)
[IO.File]::WriteAllText((Join-Path $OutDir 'guardrail-edge.reg'), (New-RegFile 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge' 'InPrivateModeAvailability'), [Text.Encoding]::Unicode)

$policy = [ordered]@{
    ExtensionInstallForcelist = @("$ExtensionId;$UpdateUrl")
    URLBlocklist              = $blocklist
    IncognitoModeAvailability = 1
    BrowserGuestModeEnabled   = $false
    '3rdparty'                = @{ extensions = @{ $ExtensionId = [ordered]@{
                gatewayUrl = $origin; failMode = $FailMode; uploadPolicy = $UploadPolicy; enabled = $true } } }
}
$json = $policy | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $OutDir 'guardrail-policy.json'), $json, (New-Object Text.UTF8Encoding $false))

$net = @('# AI services to block at the DNS filter / web proxy for every device.',
    '# Browser AI sites (covered and uncovered) - allow the covered ones only where the',
    '# managed browser with the extension is enforced:') +
    @($domains.covered_by_extension | ForEach-Object { "# covered: $_" }) +
    @($blocklist | ForEach-Object { ($_ -split '/')[0] } | Sort-Object -Unique) +
    @('', '# Provider APIs: allow ONLY from the guardrail gateway host:') +
    @($domains.provider_apis_gateway_only)
[IO.File]::WriteAllText((Join-Path $OutDir 'ai-blocklist.txt'), (($net -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))

# Update manifest for a self-hosted .crx (served at -UpdateUrl).
if ($CrxUrl) {
    if ($CrxUrl -notmatch '^https://') { throw 'CrxUrl must use https://' }
    $manifest = Get-Content -Raw -Encoding UTF8 (Join-Path $PSScriptRoot '..\..\extension\src\manifest.json') | ConvertFrom-Json
    $xml = @"
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$ExtensionId'>
    <updatecheck codebase='$([Security.SecurityElement]::Escape($CrxUrl))' version='$($manifest.version)' />
  </app>
</gupdate>
"@
    [IO.File]::WriteAllText((Join-Path $OutDir 'updates.xml'), $xml, (New-Object Text.UTF8Encoding $false))
}

Write-Host "Policy files written to $OutDir" -ForegroundColor Green
