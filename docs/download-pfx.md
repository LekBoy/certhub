# Assinar pelo InfraHub e/ou descarregar o .pfx

Cada certificado de assinatura tem **dois controlos independentes**, definidos pelo administrador:

| Controlo | Onde | O que permite |
|---|---|---|
| **Quem pode assinar através do InfraHub** | certificado → *Quem pode assinar* (grupos; vazio = qualquer utilizador com «Assinar ficheiros») | Enviar ficheiros à página ou à API e receber o ficheiro assinado. A chave nunca sai do servidor. |
| **Quem pode descarregar o .pfx** | certificado → *Quem pode descarregar o .pfx* (grupos; **vazio = ninguém**) | Descarregar o .pfx com a chave privada. |

Um grupo pode ter só um, só o outro, ou os dois: marque-o numa ou nas duas listas. Para descarregar também
é preciso a permissão **«Descarregar o .pfx»** no grupo (*Administração → Grupos*), que só o grupo Administradores traz por defeito.

## Preparar o servidor (uma vez)

1. Gerar a chave de cifra e pô-la no `.env`:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` → `INFRAHUB_FILE_KEY=...`
2. Guardar uma cópia dessa chave no cofre. Sem ela, os .pfx guardados não se decifram. Para rodar a chave,
   ponha a nova primeiro e a antiga a seguir, separadas por vírgula (`nova,antiga`).
3. Reiniciar o site (o `.env` só é lido no arranque).

## Guardar um .pfx para descarga

*Certificados → Registar certificado* (ou editar): enviar o .pfx e a palavra-passe e marcar
**«Guardar o .pfx cifrado…»**. Depois escolher os grupos que o podem descarregar.

- O ficheiro fica **cifrado** na base de dados. A palavra-passe **nunca** é guardada: entregue-a por outro canal.
- Só se guarda se o .pfx tiver a chave privada.
- «Apagar o .pfx guardado» remove-o (os dados públicos do certificado ficam).

## Para o dev

*Certificados de assinatura*: a coluna **«Para si»** mostra o que pode fazer com cada certificado (*Assinar* e/ou *.pfx*).
Se pode descarregar, aparece o botão **Descarregar .pfx**. Cada descarga (e cada tentativa negada) fica na **Auditoria**.

## Aviso

Quem descarrega o .pfx fica com a chave privada: pode assinar fora do InfraHub, sem registo, e uma cópia perdida
é uma chave comprometida. Dê esta permissão só a quem precisa, e prefira a assinatura pelo InfraHub sempre que possível.
