# callcenterultazap
Sistema de atendimento via whatsapp

Sistema de atendimento via WhatsApp com regras de negocio centrais implementadas.

## Canais omnichannel suportados

- WhatsApp
- Telegram
- Instagram
- Facebook Messenger
- E-mail
- Chat para site

## Funcionalidades implementadas

- Cadastro de contatos com normalizacao de telefone.
- Abertura de ticket com fila de atendimento.
- Atribuicao de ticket para agente.
- Mudanca de status (`open`, `pending`, `resolved`).
- Registro de mensagens por ticket.
- Reabertura automatica para `pending` quando cliente responde em ticket resolvido.
- Filtros de listagem por status e fila.
- Metricas gerais (contatos, tickets, mensagens e resumo por status).

## Estrutura

- `src/callcenter.py`: nucleo de dominio e regras.
- `src/ultazap.py`: servicos de automacao, produtividade e gestao do UltaZap.
- `src/erp.py`: contrato unico ERP (`ERPClient`), provedores e orquestrador (`ERPIntegrationService`).
- `src/cli.py`: exemplo de uso executavel.
- `tests/test_callcenter.py`: testes unitarios do fluxo principal.
- `tests/test_ultazap.py`: testes fim a fim para funcionalidades UltaZap e integracao ERP.

## Recursos UltaZap implementados

- ChatGPT (sugestao de resposta automatica de contexto).
- CRM (contato + campos customizaveis).
- Bot (primeiro contato automatizado).
- Agendamento de mensagens (processamento por horario).
- Filtros por status, fila, etiqueta e agente.
- Envio de midias (image, video, gif, sticker, file).
- Grupos de agentes com controle de visibilidade por conversa.
- Frases rapidas.
- Etiquetas.
- Relatorios consolidados.
- Campanhas de envio em massa.
- Permissoes por agente.
- Chat interno da equipe.
- Notas privadas por ticket.

## Primeiro acesso

- Usuario: `master`
- Senha: `admin123`

Recomendacao: altere a senha padrao apos o primeiro login.

## Painel do operador (ERP)

- Exibe no painel se o cliente possui pendencia financeira quando a integracao ERP estiver ativa.
- Permite enviar boleto via chat quando houver pendencia.
- Permite desbloqueio em cobranca para operadores com permissao `billing:unlock`.
- Exibe dados de conexao do cliente no painel.

## Painel de atendimento

- Transferir atendimento para outro operador.
- Finalizar atendimento com bloqueio de novas acoes para aquela conversa.

## Webhook e observabilidade

- Endpoint dedicado para webhook WhatsApp: `/api/webhook/evolution`.
- Endpoint unificado para inbound omnichannel: `POST /api/webhook/inbound`.
- Validacao por token opcional via header `X-Webhook-Token` com `WEBHOOK_TOKEN`.
- Idempotencia por `event_key` persistida em SQLite (`webhook_events`).
- Fila em memoria + worker para processamento assinc.
- Backpressure de webhook com limite de fila e resposta `503` quando saturada.
- Limpeza automatica de eventos antigos ja processados.
- Reprocessamento de pendentes: `POST /api/webhook/reprocess` (admin).
- Logs estruturados JSON por request e por evento.
- Tracing simples por `X-Request-ID`.
- Metricas Prometheus em `/metrics`.
- Healthcheck em `/health`.
- Troca de senha obrigatoria para credencial padrao em `POST /api/change-password`.
- Rate limit de tentativas de login (retorno `429` com `Retry-After`).
- Limite de payload JSON para reduzir risco de abuso (`413`).
- Atualizacao em tempo real via SSE em `GET /api/events`.
- SLA operacional em `GET /api/sla` (resumo + visao por fila).
- Dashboard inteligente em `GET /api/dashboard/intelligence` (score, alertas, carga por fila e operadores).
- Gestao de TMA/TME em `GET /api/tma-tme` (resumo, conformidade, visao por fila e operador).
- Metas de TMA/TME por fila em `GET/POST /api/tma-tme/targets` (admin).
- Frases rapidas via API (`GET/POST /api/quick-replies`) e envio por conversa (`POST /api/customers/{id}/quick-reply`).
- Notas privadas por cliente (`GET/POST /api/customers/{id}/notes`).
- Agendamento de mensagens por cliente (`POST /api/customers/{id}/schedule-message`) com worker dedicado.
- Listagem e cancelamento de agendamentos (`GET /api/customers/{id}/scheduled-messages`, `POST /api/scheduled-messages/{id}/cancel`).
- Midias por atendimento (`GET/POST /api/customers/{id}/media`) com registro no historico.
- Upload de midia por arquivo base64 (`POST /api/customers/{id}/media-upload`) com publicacao local em `/uploads/*`.
- Chat interno da equipe (`GET/POST /api/team-messages`).
- Sugestao de resposta por IA (`POST /api/customers/{id}/ai-suggest`) com fallback local quando OpenAI nao estiver configurada.
- Opt-out de campanhas por cliente (`POST /api/customers/{id}/campaign-opt-out`, admin).
- Campanhas em massa com fila, agendamento e taxa (`GET/POST /api/campaigns`).
- Exportacao CSV de campanha (`GET /api/campaigns/{id}/export`).

## Integracao completa com ERPs

Provedores implementados:

- IXC Soft
- Hubsoft
- MK Solutions
- Voalle
- SGP

Camada padronizada:

- Contrato unico `ERPClient` para:
  - Buscar cliente
  - Listar faturas em aberto
  - Abrir chamado
  - Healthcheck
- Modelos canonicos desacoplados dos payloads nativos.
- `ERPIntegrationService` para orquestracao de bot/atendimento.

## Executar testes

```powershell
& "C:\Users\Pedro Henrique\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m unittest discover -s tests -p "test_*.py" -v
```

## Executar exemplo de uso

```powershell
& "C:\Users\Pedro Henrique\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m src.cli
```

## Executar servidor web

```powershell
& "C:\Users\Pedro Henrique\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" app.py
```

URL local padrao:

```text
http://127.0.0.1:8000
```

Variaveis de ambiente uteis:

- `PORT`: porta HTTP (default `8000`)
- `WEBHOOK_TOKEN`: valida webhook pelo header `X-Webhook-Token`
- `EVOLUTION_BASE_URL`
- `EVOLUTION_API_KEY`
- `EVOLUTION_INSTANCE`
- `SESSION_TTL_SECONDS`: duracao da sessao autenticada (default `86400`)
- `SESSION_COOKIE_SECURE`: define cookie `Secure` (`1` para habilitar)
- `MAX_JSON_BYTES`: limite de payload JSON por requisicao (default `1048576`)
- `MAX_WEBHOOK_QUEUE_SIZE`: limite da fila em memoria do worker webhook (default `2000`)
- `LOGIN_RATE_LIMIT_ATTEMPTS`: numero maximo de tentativas de login por janela (default `8`)
- `LOGIN_RATE_LIMIT_WINDOW_SECONDS`: janela de rate limit do login em segundos (default `300`)
- `WEBHOOK_PROCESSED_RETENTION_SECONDS`: retencao de eventos processados em segundos (default `604800`)
- `WEBHOOK_MAX_ATTEMPTS`: maximo de tentativas de processamento antes de dead-letter logico (default `5`)
- `DEFAULT_SLA_FIRST_RESPONSE_SECONDS`: alvo de SLA para 1a resposta (default `900`)
- `DEFAULT_TME_TARGET_SECONDS`: meta global inicial de TME em segundos (default `300`)
- `DEFAULT_TMA_TARGET_SECONDS`: meta global inicial de TMA em segundos (default `1200`)
- `SCHEDULE_WORKER_POLL_SECONDS`: intervalo de varredura do worker de agendamento (default `2`)
- `MAX_UPLOAD_BYTES`: tamanho maximo para upload de arquivo em bytes (default `10485760`)
- `OPENAI_API_KEY`: chave para endpoint de sugestao IA
- `OPENAI_MODEL`: modelo OpenAI para sugestoes (default `gpt-5-mini`)
- `SSE_KEEPALIVE_SECONDS`: intervalo de keepalive SSE (default `15`)
- `SSE_SUBSCRIBER_QUEUE_MAX`: backlog maximo por assinante SSE (default `200`)
