# Certificado Code Signing com CA interna (AD CS)

Objetivo: o certificado `1.3.6.1.5.5.7.3.3 (Code Signing)` é emitido pela CA interna e a **private key nasce e fica no
servidor de assinatura, não exportável**. Nunca existe um `.pfx` para entregar a ninguém; os devs só usam o CertHub.

> Os scripts `scripts/windows/*.ps1` ainda não foram executados num ambiente real. Experimente primeiro com um
> certificado de teste (ou um template de teste) antes de pedir o definitivo.

```
 AD CS (CA interna) ──emite──▶ servidor de assinatura (key não exportável, store LocalMachine\My)
                                       │  SignTool
 dev ──upload──▶ CertHub ──────────────┘──▶ ficheiro assinado ──▶ dev
```

## 1. Template no AD CS (feito por quem gere a CA)

Na consola *Certification Authority → Certificate Templates → Manage*, **duplicar** o template *Code Signing*
(o original é v1 e não permite estas definições). Sugestão de nome: `CertHubCodeSigning`.

| Separador | Definição |
|---|---|
| Compatibility | CA e destinatário: Windows Server 2016 ou superior |
| General | Validade **3 anos** (ajustável; 3–5 anos é um bom equilíbrio), renovação 6 semanas |
| Request Handling | Purpose: *Signature*. **Desmarcar** *Allow private key to be exported* |
| Cryptography | *Key Storage Provider*, RSA, mínimo **3072** bits, SHA-256 |
| Subject Name | *Supply in the request* |
| Extensions → Application Policies | só **Code Signing** (`1.3.6.1.5.5.7.3.3`) |
| Issuance Requirements | (recomendado) *CA certificate manager approval*: um humano aprova cada emissão |
| Security | **Read + Enroll** só para a conta de computador do servidor de assinatura (não *Domain Computers*) |

Depois: *Certificate Templates → New → Certificate Template to Issue → CertHubCodeSigning*.

## 2. Pedir o certificado no servidor de assinatura

Em PowerShell **como Administrador**, no servidor de assinatura:

```powershell
cd scripts\windows
.\New-SigningCertificate.ps1 `
    -CAConfig  "ca01.empresa.local\Empresa Issuing CA" `   # certutil -config - -ping  lista as CAs
    -Template  "CertHubCodeSigning" `
    -Subject   "CN=Empresa PAD Code Signing,O=Empresa,C=PT" `
    -ServiceAccount "EMPRESA\svc-certhub"                  # conta que corre a app
```

O script gera a key (não exportável), o pedido com o EKU Code Signing, submete à CA, instala o certificado em
`LocalMachine\My`, confirma o EKU, dá leitura da key à conta de serviço e exporta o **`.cer` público**
(`scripts\windows\out\<thumbprint>.cer`).

Se o template exige aprovação, o script pára com o `RequestId`. O gestor da CA emite o pedido em
*Pending Requests → Issue* e depois corre-se `.\New-SigningCertificate.ps1 -Accept -CAConfig ... -RequestId <id>`.

## 3. Registar no CertHub

Admin → **Signing certificates → Adicionar**: enviar o `.cer` público. O CertHub rejeita-o se não tiver o EKU Code Signing
e lê thumbprint, titular e validade do próprio certificado.

## 4. Servidor de assinatura

- Windows Server com **Windows SDK** (SignTool). Ajustar `SIGNTOOL_PATH` se não estiver no caminho por omissão.
- A app deve correr com a conta de serviço a que deu permissão na key (`-ServiceAccount`), **não** como Administrador.
- Timestamp: ver abaixo (`SIGN_TIMESTAMP_URL`).

## 5. Confiança (para a assinatura ser aceite)

A CA raiz tem de ser confiável em todas as máquinas que verificam ou correm o código, e no servidor de assinatura se
`SIGN_VERIFY=1`.

- **CA Enterprise (AD CS integrada no domínio):** a raiz já é distribuída às máquinas do domínio automaticamente.
  Confirmar com `certutil -viewstore -enterprise root`.
- **CA offline / raiz fora do AD:** distribuir por GPO: *Computer Configuration → Policies → Windows Settings →
  Security Settings → Public Key Policies → Trusted Root Certification Authorities*.
- **Trusted Publishers** (opcional, evita avisos de "editor"): importar o `.cer` público do certificado de assinatura por GPO,
  em *Public Key Policies → Trusted Publishers*.

## 6. Testar

No servidor de assinatura, **com a conta de serviço** (ex.: `runas /user:EMPRESA\svc-certhub powershell`):

```powershell
.\Test-Signing.ps1 -Thumbprint <thumbprint>
```

Assina um ficheiro descartável com o mesmo comando que o CertHub usa e corre `signtool verify /pa`.
Exit 0 = tudo certo. Exit 2 = assinou mas a CA raiz não é confiável nesta máquina (§5).

## 7. Timestamp e expiração

Sem timestamp a assinatura deixa de valer quando o certificado expira; com timestamp RFC 3161 continua válida.
`SIGN_TIMESTAMP_URL` vem vazio por omissão. Para assinaturas duradouras, use um TSA que o servidor consiga alcançar
(público, se a política de rede permitir, ou um TSA interno). Funciona com certificados internos em ambos os casos.

## 8. Renovação

1. ~60 dias antes de expirar (o painel do CertHub mostra o aviso a 30 dias): repetir §2 com a CA (nova key, novo thumbprint).
2. Registar o novo `.cer` no CertHub e desativar o antigo.
3. Os ficheiros já assinados **com timestamp** continuam válidos; os sem timestamp têm de ser reassinados.

## Problemas comuns

| Sintoma | Causa provável |
|---|---|
| `SignTool Error: No certificates were found that met all the given criteria` | Thumbprint errado, ou store/`/sm` não corresponde (LocalMachine vs CurrentUser) |
| `Keyset does not exist` / `Access denied` | A conta que corre a app não tem leitura da key (§2 `-ServiceAccount`) |
| `A certificate chain could not be built to a trusted root` | Raiz não confiável no servidor: §5, ou `SIGN_VERIFY=0` |
| CertHub: «não tem a utilização Code Signing» | Template sem a Application Policy Code Signing (§1) |
| Pedido recusado / `template not found` | Template não publicado na CA, ou sem permissão *Enroll* para o servidor |
