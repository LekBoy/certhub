<#
.SYNOPSIS
  Pede ao AD CS um certificado Code Signing cuja private key nasce NÃO EXPORTÁVEL no servidor de assinatura.

.DESCRIPTION
  Correr no servidor de assinatura, como Administrador. Passos:
    1. gera a key (RSA, CNG, LocalMachine, não exportável) e o pedido (CSR) com o EKU Code Signing 1.3.6.1.5.5.7.3.3
    2. submete o pedido à CA interna com o template indicado
    3. se emitido, instala o certificado em LocalMachine\My e exporta o .cer PÚBLICO (é este que vai para o CertHub)
    4. opcionalmente dá à conta de serviço da app permissão de leitura da private key
  Nunca existe um .pfx. Se o template exigir aprovação de um gestor da CA, o script pára e diz como continuar (-Accept).

.EXAMPLE
  .\New-SigningCertificate.ps1 -CAConfig "ca01.empresa.local\Empresa Issuing CA" -Template "CertHubCodeSigning" `
      -Subject "CN=Empresa PAD Code Signing,O=Empresa,C=PT" -ServiceAccount "EMPRESA\svc-certhub"

.EXAMPLE
  # depois de o gestor da CA aprovar o pedido pendente:
  .\New-SigningCertificate.ps1 -Accept -CAConfig "ca01.empresa.local\Empresa Issuing CA" -RequestId 123
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $CAConfig,                     # "servidor\Nome da CA" (ver: certutil -dump / certutil -config - -ping)
    [string] $Template = "CertHubCodeSigning",                     # NOME (não o display name) do template no AD CS
    [string] $Subject = "CN=Code Signing,O=Empresa,C=PT",
    [ValidateSet(3072, 4096)] [int] $KeyLength = 3072,
    [string] $ServiceAccount,                                       # conta que corre a app, ex.: EMPRESA\svc-certhub
    [string] $OutDir = (Join-Path $PSScriptRoot "out"),
    [switch] $Accept,                                               # continuar um pedido que ficou pendente
    [int] $RequestId
)

$ErrorActionPreference = "Stop"
$CodeSigningOid = "1.3.6.1.5.5.7.3.3"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Execute como Administrador (a key é criada no store LocalMachine)."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$inf = Join-Path $OutDir "request.inf"
$req = Join-Path $OutDir "request.req"
$cer = Join-Path $OutDir "issued.cer"

function Invoke-Certreq {
    param([string[]] $Arguments)
    $ErrorActionPreference = "Continue"   # certreq escreve em stderr mesmo em sucesso
    $out = & certreq.exe @Arguments 2>&1 | Out-String
    Write-Host $out
    return $out
}

if (-not $Accept) {
    @"
[Version]
Signature = "`$Windows NT`$"

[NewRequest]
Subject = "$Subject"
KeyAlgorithm = RSA
KeyLength = $KeyLength
HashAlgorithm = SHA256
Exportable = FALSE
MachineKeySet = TRUE
KeyUsage = 0x80
RequestType = PKCS10
ProviderName = "Microsoft Software Key Storage Provider"

[Extensions]
2.5.29.37 = "{text}"
_continue_ = "$CodeSigningOid"
"@ | Set-Content -Path $inf -Encoding Unicode

    Remove-Item $req, $cer -ErrorAction SilentlyContinue
    Write-Host "==> A gerar key não exportável e pedido..." -ForegroundColor Cyan
    Invoke-Certreq @("-new", "-f", $inf, $req) | Out-Null

    Write-Host "==> A submeter à CA $CAConfig (template $Template)..." -ForegroundColor Cyan
    $out = Invoke-Certreq @("-submit", "-f", "-config", $CAConfig, "-attrib", "CertificateTemplate:$Template", $req, $cer)

    if (-not (Test-Path $cer)) {
        Write-Warning "O pedido ficou PENDENTE (o template exige aprovação, ou foi recusado). Veja o RequestId acima."
        Write-Warning "Depois de o gestor da CA emitir:  .\New-SigningCertificate.ps1 -Accept -CAConfig '$CAConfig' -RequestId <id>"
        return
    }
} else {
    if (-not $RequestId) { throw "-Accept requer -RequestId." }
    Remove-Item $cer -ErrorAction SilentlyContinue
    Write-Host "==> A obter o certificado emitido (pedido $RequestId)..." -ForegroundColor Cyan
    Invoke-Certreq @("-retrieve", "-f", "-config", $CAConfig, "$RequestId", $cer) | Out-Null
    if (-not (Test-Path $cer)) { throw "Certificado ainda não emitido." }
}

Write-Host "==> A instalar em LocalMachine\My (liga à key criada)..." -ForegroundColor Cyan
Invoke-Certreq @("-accept", "-machine", $cer) | Out-Null

$issued = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $issued.Thumbprint
if (-not $cert) { throw "Certificado não encontrado no store após -accept." }
if (-not $cert.HasPrivateKey) { throw "O certificado foi instalado sem private key associada." }
if ($cert.EnhancedKeyUsageList.ObjectId -notcontains $CodeSigningOid) {
    throw "O certificado emitido NÃO tem o EKU Code Signing ($CodeSigningOid). Verifique o template."
}

$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

# Confirma que a key é mesmo não exportável
if ($rsa -is [System.Security.Cryptography.RSACng] -and
    $rsa.Key.ExportPolicy -ne [System.Security.Cryptography.CngExportPolicies]::None) {
    Write-Warning "A private key parece EXPORTÁVEL. Corrija o template (Request Handling) antes de usar em produção."
}

# Permissão de leitura da key para a conta que corre a app
if ($ServiceAccount) {
    $keyName = $rsa.Key.UniqueName
    $keyFile = Get-ChildItem "$env:ProgramData\Microsoft\Crypto\Keys" -Filter $keyName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $keyFile) { $keyFile = Get-ChildItem "$env:ProgramData\Microsoft\Crypto\SystemKeys" -Filter $keyName -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if ($keyFile) {
        & icacls.exe $keyFile.FullName /grant "${ServiceAccount}:(R)" | Out-Null
        Write-Host "==> Leitura da key concedida a $ServiceAccount" -ForegroundColor Cyan
    } else {
        Write-Warning "Ficheiro da key não encontrado; dê permissão manualmente (certlm.msc > Todas as tarefas > Gerir chaves privadas)."
    }
}

$publicCer = Join-Path $OutDir "$($cert.Thumbprint).cer"
Export-Certificate -Cert $cert -FilePath $publicCer -Type CERT | Out-Null

Write-Host ""
Write-Host "Certificado pronto." -ForegroundColor Green
Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Válido até : $($cert.NotAfter)"
Write-Host "  Registar no CertHub (admin > Signing certificates) este ficheiro PÚBLICO: $publicCer"
