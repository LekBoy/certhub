# DigiCert KeyLocker no InfraHub (módulo CertHub)

A chave privada fica num HSM na cloud da DigiCert e nunca sai de lá. O servidor de assinatura só precisa do
**SignTool** (Windows SDK) e do cliente **`smctl`** da DigiCert, que liga o SignTool ao KeyLocker.

> Os comandos vêm da documentação da DigiCert e não foram testados neste repositório (não há SignTool nem KeyLocker
> no ambiente de desenvolvimento). Valide primeiro com o botão **«Testar assinatura»** do certificado.

## 1. No servidor de assinatura (com a conta de serviço)

Variáveis de ambiente **da conta de serviço** (nunca na base de dados nem no CertHub; a página *Definições* só mostra
se estão definidas). Os nomes são os da documentação do `smctl`, a confirmar na vossa conta:

```powershell
$env:SM_HOST                 = "<URL indicado pela DigiCert>"
$env:SM_API_KEY              = "<api key>"
$env:SM_CLIENT_CERT_FILE     = "C:\infrahub\secrets\client-auth.p12"
$env:SM_CLIENT_CERT_PASSWORD = "<palavra-passe do .p12>"
```

Preparação, uma única vez:

```powershell
smctl windows ksp register            # como Administrador
smctl healthcheck
certutil.exe -csp "DigiCert Software Trust Manager KSP" -key -user   # confirma o nome do provider (KSP)
smctl windows certsync --keypair-alias=<alias>                       # só para o método «por thumbprint»
```

O nome do provider aparece de duas formas na documentação ("Software Trust Manager" / "Signing Manager"): use o que o
`certutil` mostrar na máquina.

## 2. No CertHub: Certificados → Registar certificado

1. Envie o `.cer` **público** (exportado do portal da DigiCert).
2. Escolha o método:
   - **DigiCert KeyLocker: por thumbprint** – corre `signtool sign /sha1 <thumbprint> /fd SHA256 [/tr ...] ficheiro`
     (precisa do `certsync`; o certificado fica no store do utilizador que o correu, por isso a app tem de correr com essa conta).
   - **DigiCert KeyLocker: por alias da chave** – corre `signtool sign /csp "<KSP>" /kc <alias> /f <ficheiro.cer> /fd SHA256 ...`
     (preencha o provider, o alias e o caminho do `.cer` no servidor).
   - **Comando personalizado** – um argumento por linha, com os marcadores `{signtool} {file} {thumbprint} {alias} {csp} {cert_file} {timestamp_url} {store}`.
3. A pré-visualização do comando aparece na página; **«Testar assinatura»** assina um ficheiro descartável e mostra o output.
4. Defina **limite anual** e **datas de subscrição/renovação** quando as souber: o painel avisa a 80 % e a 100 % do limite
   e 30 dias antes da renovação. Em *Definições* pode ligar «bloquear assinaturas ao atingir o limite».

## 3. Timestamp

`http://timestamp.digicert.com` em *Definições* (ou por certificado). Com timestamp as assinaturas continuam válidas
depois de o certificado expirar.
