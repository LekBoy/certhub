# Deploy em produção: Windows Server + IIS + PostgreSQL

Branch: `production`. Ordem: preparar a máquina → PostgreSQL → aplicação → IIS → DigiCert → testar.

## 1. Software na VM
IIS (`Install-WindowsFeature -Name Web-Server -IncludeManagementTools`), Python 3.13 (64 bits, **para todos os utilizadores**, com PATH), Git,
Windows SDK (só "Signing Tools for Desktop Apps"), HttpPlatformHandler 1.2 (depois `iisreset`), PostgreSQL 17 e,
quando houver certificado emitido, o DigiCert Software Trust Manager (`smctl`).

## 2. PostgreSQL
No pgAdmin (Query Tool, ligado à base `postgres`), uma instrução de cada vez:

```sql
CREATE ROLE infrahub WITH LOGIN PASSWORD '<palavra-passe-forte>';
CREATE DATABASE infrahub OWNER infrahub ENCODING 'UTF8';
```

## 3. Aplicação
```powershell
git clone -b production https://github.com/LekBoy/certhub.git C:\infrahub
cd C:\infrahub
python -m venv venv
venv\Scripts\pip install -r requirements-prod.txt
mkdir logs, secrets
copy .env.production.example .env   # preencher os <...>. O .env nunca vem do Git; gere uma DJANGO_SECRET_KEY nova
venv\Scripts\python manage.py migrate
venv\Scripts\python manage.py createsuperuser
venv\Scripts\python manage.py collectstatic --noinput
```

`.env` mínimo de produção:

```
DJANGO_SECRET_KEY=<aleatório longo>
DJANGO_ALLOWED_HOSTS=infrahub.empresa.pt,localhost
DJANGO_CSRF_TRUSTED_ORIGINS=https://infrahub.empresa.pt
DB_ENGINE=postgresql
DB_PASSWORD=<palavra-passe do utilizador infrahub>
SIGNTOOL_PATH=C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe
```
Não defina `DJANGO_DEBUG` (com `DJANGO_DEBUG=1` a aplicação mostra erros detalhados). Nunca reutilize a chave secreta de desenvolvimento. O `.env` só deve ser legível pela conta do Application Pool e pelos administradores.

Teste a aplicação sozinha antes do IIS:
`venv\Scripts\waitress-serve --listen=127.0.0.1:8000 config.wsgi:application` → http://127.0.0.1:8000

## 4. IIS
1. Application Pool `InfraHub`: *No Managed Code*; **Identity** = a conta que vai usar o DigiCert; **Load User Profile = True**.
2. Site apontando para `C:\infrahub` (o `web.config` já vem no repositório) com o Application Pool `InfraHub`.
3. Binding **https (443)** com um certificado do servidor. Não crie binding http, ou use URL Rewrite para redirecionar para https.
4. Permissões: a conta do pool com *Modificar* em `C:\infrahub\logs` e *Ler* no resto, em `secrets` e no `.env`.

O `web.config` arranca o waitress em `127.0.0.1` (porta interna), com limite de upload de 200 MB e timeout de 10 minutos.

## 5. DigiCert (quando o certificado estiver emitido)
Com **a mesma conta do Application Pool** (a loja de certificados é por utilizador): definir `SM_HOST`, `SM_API_KEY`,
`SM_CLIENT_CERT_FILE`, `SM_CLIENT_CERT_PASSWORD` no `.env`, e correr `smctl healthcheck` e `smctl windows certsync`.
Ver `docs/digicert-keylocker.md`.

## 6. Atualizar para uma nova versão
```powershell
cd C:\infrahub
git pull
venv\Scripts\pip install -r requirements-prod.txt
venv\Scripts\python manage.py migrate
venv\Scripts\python manage.py collectstatic --noinput
iisreset
```
Antes de migrar, faça cópia da base: `pg_dump -U infrahub -h localhost infrahub > backup.sql`.

## Verificação
`venv\Scripts\python manage.py check --deploy` (os avisos de HSTS preload/subdomínios são opcionais).
Erros 500/502: ver `C:\infrahub\logs\waitress.log` e o Event Viewer.
