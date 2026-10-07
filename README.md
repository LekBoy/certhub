# certhub

Inventário de certificados das VMs + **serviço de assinatura de código** (SignTool).

## Assinatura de código (sem entregar o .pfx)

Os devs enviam o ficheiro (.dll, .exe, .msi, .cab, .nupkg, ...) e recebem-no assinado (SHA-256).
A private key **nunca sai do servidor de assinatura**.

**Setup (servidor Windows com Windows SDK / SignTool):**
1. Importar o `.pfx` no certificate store (LocalMachine\My) como **não exportável**; idealmente a CA entrega a key em HSM/token.
2. No admin, criar *Signing certificate* enviando só o `.cer` público. É rejeitado se não tiver o EKU
   Code Signing `1.3.6.1.5.5.7.3.3`. Thumbprint e validade são lidos do certificado.
3. Dar a permissão `signing | signing request | Pode assinar ficheiros` aos devs e criar um *Signing token* (Bearer, 90 dias) para pipelines.
4. Variáveis: `SIGNTOOL_PATH`, `SIGN_TIMESTAMP_URL` (opcional), `SIGN_VERIFY`, `SIGN_MAX_UPLOAD_MB`.

**Uso:**
- Web: `/sign/` (login). 
- Pipeline: `curl -H "Authorization: Bearer $TOKEN" -F file=@Foo.dll -F certificate=1 -o Foo.dll.signed https://certhub/api/sign/`

Cada pedido fica auditado (utilizador, ficheiro, SHA-256 antes/depois, certificado). Servir sempre atrás de HTTPS.

## Interface e utilizadores

UI em Tailwind CSS (painel, certificados, assinar, histórico, tokens). O CSS compilado vai commitado em `static/css/app.css`;
só é preciso Node para o alterar: `npm install && npm run build:css` (ou `npm run watch:css`).

- **Utilizadores**: Django admin (`/admin/auth/user/`). Grupos criados automaticamente:
  - **Assinantes** – podem assinar ficheiros e gerir os seus próprios tokens. Há ações em massa para dar/retirar o grupo e desativar utilizadores
    (utilizadores desativados deixam logo de poder usar tokens).
  - **Auditores** – veem o histórico de assinaturas de todos (os restantes só vêem o seu).
- Produção: `pip install -r requirements.txt`, `python manage.py migrate`, `collectstatic` (servido por WhiteNoise), `DJANGO_DEBUG=0`.

## Certificado interno e timestamp

Com um certificado emitido pela CA interna não é preciso (nem útil) usar um TSA público:
- `SIGN_TIMESTAMP_URL` vem **vazio** por omissão → assina sem timestamp. Atenção: sem timestamp a assinatura deixa de ser válida quando o certificado expira
  (ficheiros já distribuídos teriam de ser reassinados).
- Para assinaturas duradouras, aponte para um TSA RFC 3161 acessível internamente (ex.: `SIGN_TIMESTAMP_URL=http://tsa.empresa.local/tsa`).
  Qualquer TSA serve com certificados internos; só é preciso rede até ele.
- Máquinas que verifiquem as assinaturas têm de confiar na CA raiz interna (GPO / import no store *Trusted Root*).
  O mesmo vale para o servidor de assinatura se `SIGN_VERIFY=1`; senão use `SIGN_VERIFY=0`.
