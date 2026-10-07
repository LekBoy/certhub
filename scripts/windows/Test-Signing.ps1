<#
.SYNOPSIS
  Testa a assinatura com o MESMO comando que o CertHub usa, num ficheiro .ps1 descartável.
  Correr no servidor de assinatura, com a conta que corre a app (para validar o acesso à key).

.EXAMPLE
  .\Test-Signing.ps1 -Thumbprint A1B2C3...
  .\Test-Signing.ps1 -Thumbprint A1B2C3... -TimestampUrl http://tsa.empresa.local/tsa
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Thumbprint,
    [string] $SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
    [string] $TimestampUrl = "",
    [string] $Store = "My",
    [switch] $CurrentUserStore
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $SignTool)) { throw "SignTool não encontrado em $SignTool (instale o Windows SDK e ajuste -SignTool / SIGNTOOL_PATH)." }

$file = Join-Path ([IO.Path]::GetTempPath()) "certhub-test-$([guid]::NewGuid().ToString('N')).ps1"
"Write-Output 'certhub test'" | Set-Content $file

try {
    $signArgs = @("sign", "/fd", "SHA256", "/sha1", $Thumbprint, "/s", $Store)
    if (-not $CurrentUserStore) { $signArgs += "/sm" }
    if ($TimestampUrl) { $signArgs += @("/tr", $TimestampUrl, "/td", "SHA256") }
    $signArgs += $file

    Write-Host "==> signtool $($signArgs -join ' ')" -ForegroundColor Cyan
    & $SignTool @signArgs
    if ($LASTEXITCODE -ne 0) { throw "signtool sign falhou ($LASTEXITCODE)" }

    Write-Host "==> signtool verify /pa" -ForegroundColor Cyan
    & $SignTool verify /pa $file
    $verifyExit = $LASTEXITCODE

    $sig = Get-AuthenticodeSignature $file
    Write-Host ""
    Write-Host "Estado Authenticode: $($sig.Status)  (assinante: $($sig.SignerCertificate.Subject))"
    Write-Host "Timestamp: $(if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { 'sem timestamp' })"

    if ($verifyExit -ne 0) {
        Write-Warning "A assinatura foi feita mas NÃO é confiável nesta máquina: provavelmente falta a CA raiz em Trusted Root. Ver docs/internal-ca-setup.md §5. (Se não quiser verificar no servidor: SIGN_VERIFY=0)"
        exit 2
    }
    Write-Host "OK: assinatura feita e confiável." -ForegroundColor Green
}
finally {
    Remove-Item $file -ErrorAction SilentlyContinue
}
