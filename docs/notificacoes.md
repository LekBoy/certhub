# Notificações por e-mail (Outlook)

O InfraHub envia **um e-mail resumo** com os certificados que estão perto de expirar (ou já expiraram).
Cada certificado é avisado **uma só vez por limiar** (por defeito 30, 15, 7, 3 e 1 dias antes, e quando expira).
Se o certificado for renovado (nova data), os avisos recomeçam.

Configuração em **Administração → Notificações** (permissão "Gerir notificações").

## 1. Agendar o envio diário

O InfraHub não tem agendador próprio. Agende o comando uma vez por dia.

Windows (Agendador de Tarefas), no servidor do InfraHub:

```powershell
schtasks /Create /SC DAILY /ST 08:00 /TN "InfraHub - avisos de certificados" /RU <conta-de-serviço> `
  /TR "C:\infrahub\venv\Scripts\python.exe C:\infrahub\manage.py send_expiry_alerts"
```

Linux (cron): `0 8 * * * /opt/infrahub/venv/bin/python /opt/infrahub/manage.py send_expiry_alerts`

Opções do comando: `--dry-run` (mostra o que seria avisado), `--test` (e-mail de teste), `--force` (reenvia).

## 2. Como enviar para o Outlook (escolha uma)

| Opção | Quando usar | O que pedir ao responsável do Exchange / M365 |
|---|---|---|
| **SMTP relay (Connector)** — recomendada se o servidor está na rede interna | Sem palavra-passe; o Exchange aceita o IP do servidor | Um *Receive/Send Connector* a aceitar o IP do servidor InfraHub. Servidor: o do Exchange ou `<empresa>.mail.protection.outlook.com`, porta 25, segurança "Sem cifra". Utilizador vazio. |
| **Microsoft Graph** — recomendada em Microsoft 365 | Sem SMTP; autenticação moderna | Registar uma aplicação no Entra ID com permissão de aplicação `Mail.Send`, restringida a uma só caixa por *Application Access Policy*. Dar ao InfraHub: Tenant ID, Client ID e o segredo (variável `INFRAHUB_GRAPH_CLIENT_SECRET`). O "remetente" é essa caixa. |
| **SMTP autenticado** (smtp.office365.com:587, STARTTLS) | Só se o tenant ainda permitir | Uma caixa de serviço com *SMTP AUTH* ativo. A Microsoft está a retirar a autenticação básica, por isso prefira as opções acima. Palavra-passe na variável `INFRAHUB_SMTP_PASSWORD`. |

## 3. Segredos

Nunca ficam na base de dados nem aparecem no ecrã (só "Definida / Não definida"). Defina-os no ambiente da conta
de serviço (ou no `.env`): `INFRAHUB_SMTP_PASSWORD`, `INFRAHUB_GRAPH_CLIENT_SECRET`.

## 4. Verificar

1. Guarde a configuração e use **Enviar e-mail de teste**.
2. Use **Verificar agora** para correr os avisos já; em "Últimos envios" vê o resultado ou o erro.
3. Os destinatários podem ser uma lista de distribuição do Outlook.

Outros módulos entram nos avisos sem alterações aqui: basta declararem `expiry_items` no registo do módulo.
