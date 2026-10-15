# Módulos do InfraHub

O InfraHub é a plataforma de infraestrutura da BCA. Cada funcionalidade vive num **módulo**; hoje há um:
**CertHub** (assinatura de código e inventário de certificados).

## Como funcionam as permissões (duas camadas)

1. **Acesso ao módulo** (plataforma): «O Pedro pode entrar no CertHub?» Sim ou não. É a opção *Acesso ao módulo* do grupo.
   Sem acesso, o módulo não aparece no menu e todos os seus endereços (`/certhub/…`) e a API dão 403/401.
2. **Permissões dentro do módulo**: «Se entra, o que pode fazer?» (assinar, ver o histórico de todos, gerir o inventário…).
   Ter acesso não dá nenhuma por si só. E uma permissão do módulo **sem** o acesso não tem efeito.

A regra está num só sítio: `portal/backends.py` (`ModuleAccessBackend`) e `portal/middleware.py` (`ModuleAccessMiddleware`).
Os superadministradores têm sempre tudo, mas um módulo **desligado** (página *Módulos*) fica indisponível para toda a gente.

As permissões da plataforma (utilizadores, grupos, módulos, auditoria) não dependem de nenhum módulo.

## Criar um módulo novo

1. Crie uma app Django com os modelos e as vistas do módulo, e monte as URLs sob um prefixo próprio (ex.: `path("servidores/", include(...))` em `config/urls.py`).
2. Declare as permissões do módulo nos `Meta.permissions` de um dos seus modelos (ou no `PortalPermissions`), incluindo
   uma de **acesso** (ex.: `access_servidores`).
3. Registe o módulo, por exemplo num `servidores_module.py`:

   ```python
   from portal import modules
   from portal.modules import Module, NavItem

   modules.register(Module(
       key="servidores", name="Servidores", description="Inventário de servidores.", icon="archive",
       url_prefix="/servidores/", home_url_name="servidores:list",
       access_perm="portal.access_servidores",
       nav=[NavItem("Lista", "servidores:list", "archive", "servidores.view_server"),
            NavItem("Definições", "servidores:settings", "cog", "servidores.manage_server")],
       permission_groups=[("Servidores", [
           ("servidores.view_server", "Ver servidores", "Lista e detalhe."),
           ("servidores.manage_server", "Gerir servidores", "Criar, editar e apagar."),
       ])],
       dashboard=lambda request: {...},                 # opcional: dados do bloco no Painel
       dashboard_template="servidores/widget.html",     # opcional
   ))
   ```
   e chame o `register(...)` no `ready()` da app.
4. Corra `makemigrations` e `migrate`. O módulo passa a aparecer:
   - no **menu** (secção própria, só para quem tem acesso e só com os itens permitidos);
   - na **matriz de permissões** dos grupos (um cartão por módulo, com o seu «Acesso ao módulo»);
   - na página **Módulos** (ligar/desligar, utilizadores e grupos com acesso);
   - no **Painel**, se tiver `dashboard`.
5. Escreva os testes: acesso, 403 sem acesso, módulo desligado.

Ícones disponíveis para o menu: ver `portal/icons.py` (acrescente os que precisar).
