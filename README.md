# certhub

Inventário de certificados das VMs + **serviço de assinatura de código** (SignTool).

## Assinatura de código (sem entregar o .pfx)

Os devs enviam o ficheiro (.dll, .exe, .msi, .cab, .nupkg, ...) e recebem-no assinado (SHA-256 + timestamp).
A private key **nunca sai do servidor de assinatura**.

**Setup (servidor Windows com Windows SDK / SignTool):**
1. Importar o `.pfx` no certificate store (LocalMachine\My) como **não exportável**; idealmente a CA entrega a key em HSM/token.
2. No admin, criar *Signing certificate* enviando só o `.cer` público. É rejeitado se não tiver o EKU
   Code Signing `1.3.6.1.5.5.7.3.3`. Thumbprint e validade são lidos do certificado.
3. Dar a permissão `signing | signing request | Pode assinar ficheiros` aos devs e criar um *Signing token* (Bearer, 90 dias) para pipelines.
4. Variáveis: `SIGNTOOL_PATH`, `SIGN_TIMESTAMP_URL`, `SIGN_VERIFY`, `SIGN_MAX_UPLOAD_MB`.

**Uso:**
- Web: `/sign/` (login). 
- Pipeline: `curl -H "Authorization: Bearer $TOKEN" -F file=@Foo.dll -F certificate=1 -o Foo.dll.signed https://certhub/api/sign/`

Cada pedido fica auditado (utilizador, ficheiro, SHA-256 antes/depois, certificado). Servir sempre atrás de HTTPS.
