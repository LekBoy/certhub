# InfraHub

Plataforma de infraestrutura da BCA, feita de **módulos**. Cada módulo tem o seu menu, as suas páginas e as suas permissões.
Hoje há um módulo, o **CertHub** (certificados: assinatura de código e inventário). Como funcionam o acesso por módulo e
como criar novos módulos: [docs/modules.md](docs/modules.md).

- **Plataforma**: login, utilizadores, grupos, módulos (ligar/desligar), auditoria.
- **Módulo CertHub** (`/certhub/…`): assinatura de código com o SignTool, inventário de certificados, histórico, tokens de API.
- **Acesso em duas camadas**: primeiro o *acesso ao módulo* (sim/não, por grupo) e, dentro do módulo, as permissões finas.
  Sem acesso ao módulo, as permissões dele não têm efeito.
- A API de assinatura mantém-se em `POST /api/sign/` (contrato estável para os pipelines).

## Assinatura de código (sem entregar o .pfx)

Os devs enviam o ficheiro (.dll, .exe, .msi, .cab, .nupkg, ...) e recebem-no assinado (SHA-256).
A private key **nunca sai do servidor de assinatura**.

**Setup (servidor Windows com Windows SDK / SignTool):**
1. A chave privada fica não exportável no store do Windows, num HSM ou na cloud do fornecedor (ex.: DigiCert KeyLocker, ver `docs/digicert-keylocker.md`).
2. Em *Certificados → Registar certificado* envie só o `.cer` público (rejeitado se não tiver o EKU Code Signing `1.3.6.1.5.5.7.3.3`) e escolha o método de assinatura.
3. Em *Grupos* dê a permissão «Assinar ficheiros» (grupo *Assinantes*); cada utilizador cria os seus tokens (Bearer) para pipelines.
4. Valores iniciais por variável de ambiente (depois editáveis em *Definições*): `SIGNTOOL_PATH`, `SIGN_TIMESTAMP_URL` (opcional), `SIGN_VERIFY`, `SIGN_MAX_UPLOAD_MB`.

**Uso:**
- Web: `/certhub/sign/` (login).
- Pipeline: `curl -H "Authorization: Bearer $INFRAHUB_TOKEN" -F file=@Foo.dll -F certificate=1 -o Foo.dll.signed https://infrahub.empresa.pt/api/sign/`

Cada pedido fica auditado (utilizador, ficheiro, SHA-256 antes/depois, certificado). Servir sempre atrás de HTTPS.

## Inventário de certificados (só informação)

No módulo CertHub, em *Inventário* (`/certhub/inventory/`), carrega-se qualquer certificado (`.pfx/.p12`, `.crt/.cer/.der`, `.pem` com um ou vários, `.p7b`), vários de uma vez.
O CertHub lê titular, emissor, validade, domínios (SAN), tipo (TLS, Code Signing, cliente, CA…), chave, fingerprints e se é wildcard,
e guarda **só essa informação**: os ficheiros, as chaves privadas e as palavras-passe são lidos em memória e nunca guardados.
Cada certificado tem um responsável, notas e uma lista de **utilizações** (servidor, IP, porta, aplicação e ambiente; pode haver várias), e a pesquisa e os filtros também procuram por IP, servidor e aplicação. Há pesquisa, filtros (tipo, estado, servidor), exportação CSV,
avisos de expiração (≤ 30 dias) no painel e o mesmo certificado carregado outra vez só atualiza o registo.
Permissões próprias (*Ver o inventário* / *Gerir o inventário*), dentro do módulo, na matriz dos grupos.

## Interface e administração

UI em Tailwind CSS, com a identidade da BCA: azul `#193D79` e vermelho `#CC1519` (do logótipo). As cores estão em `tailwind.config.js` (`brand` e `accent`) e o logótipo e o favicon em `static/img/`; para mudar a identidade basta alterar esses ficheiros e recompilar o CSS. O CSS compilado vai commitado em `static/css/app.css`; só é preciso Node para o alterar:
`npm install && npm run build:css` (ou `npm run watch:css`).

Tudo se gere **dentro do InfraHub** (menu «Administração» e secção do módulo), segundo as permissões de cada grupo:

- **Utilizadores** – criar (palavra-passe temporária, trocada no primeiro acesso), editar, ativar/desativar, repor palavra-passe, apagar (se sem histórico).
- **Grupos** – criar/editar/apagar. Um cartão por módulo com o **«Acesso ao módulo»** e, por baixo, as permissões do módulo; mais uma secção «Plataforma» (utilizadores, grupos, módulos, auditoria). Grupos base: *Assinantes*, *Auditores*, *Administradores* (editáveis).
- **Certificados** – registar o `.cer` público **ou ler um `.pfx`** (com a palavra-passe: lê o titular, emissor, série, chave e validade e regista só os dados públicos; o ficheiro e a palavra-passe não são guardados), escolher o **método de assinatura** (store do Windows, DigiCert KeyLocker, comando personalizado), grupos com acesso, limite anual, datas de subscrição/renovação, notas e botão «Testar assinatura».
- **Definições** – SignTool, timestamp, verificação, limites de upload, extensões, validade dos tokens, bloqueio ao atingir o limite.
- **Auditoria** – quem fez o quê.
- Proteções: não é possível ficar sem nenhum utilizador ativo capaz de gerir utilizadores; ninguém dá permissões que não tem; só um superadministrador altera outro.
- O Django admin (`/admin/`) fica só para superadministradores (emergência).

O primeiro utilizador cria-se com `python manage.py createsuperuser`; depois já se gere tudo no InfraHub.
Segredos (API keys, palavras-passe) ficam em variáveis de ambiente do servidor, nunca na base de dados.

Produção: `pip install -r requirements.txt`, `python manage.py migrate`, `collectstatic` (servido por WhiteNoise), `DJANGO_DEBUG=0`.

## Certificado interno e timestamp

Com um certificado emitido pela CA interna não é preciso (nem útil) usar um TSA público:
- `SIGN_TIMESTAMP_URL` vem **vazio** por omissão → assina sem timestamp. Atenção: sem timestamp a assinatura deixa de ser válida quando o certificado expira
  (ficheiros já distribuídos teriam de ser reassinados).
- Para assinaturas duradouras, aponte para um TSA RFC 3161 acessível internamente (ex.: `SIGN_TIMESTAMP_URL=http://tsa.empresa.local/tsa`).
  Qualquer TSA serve com certificados internos; só é preciso rede até ele.
- Máquinas que verifiquem as assinaturas têm de confiar na CA raiz interna (GPO / import no store *Trusted Root*).
  O mesmo vale para o servidor de assinatura se `SIGN_VERIFY=1`; senão use `SIGN_VERIFY=0`.

Guia completo com CA interna (AD CS) e scripts PowerShell: [docs/internal-ca-setup.md](docs/internal-ca-setup.md).

Guia do DigiCert KeyLocker: [docs/digicert-keylocker.md](docs/digicert-keylocker.md).

## Notificações por e-mail

Avisos de certificados a expirar para o Outlook (SMTP ou Microsoft Graph), agendados com `python manage.py send_expiry_alerts`. Ver [docs/notificacoes.md](docs/notificacoes.md).

## Descarregar o .pfx (opcional, controlado por grupos)

Cada certificado pode permitir, por grupo, assinar pelo InfraHub e/ou descarregar o .pfx (cifrado). Ver [docs/download-pfx.md](docs/download-pfx.md).
