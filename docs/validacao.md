# Validação de produção — 13/10/2026

## Resultado

- 33 testes Python aprovados no container Python 3.12.
- 8 testes Node aprovados para a ponte Codex.
- `docker compose config` e builds de API, worker e Codex concluídos.
- API, PostgreSQL, Redis, Celery, Codex e Nginx ativos em containers.
- Somente o proxy publica 80/443; banco, broker, API e ponte permanecem internos.
- Scan Python vulnerável retornou `BLOCKED`; scan seguro retornou `PASSED`.
- Scan real de `https://example.com` foi processado pelo Celery, persistido no PostgreSQL e retornou achados de headers em relatório.
- Redis respondeu `PONG` e o worker Celery respondeu `pong`.
- Login oficial por device code conectou uma conta ChatGPT ao Codex.
- Uma revisão real Codex retornou explicação, remediação e exemplo corrigido sem mudar o Security Gate.
- Interface NULL//SENTRY dark validada visualmente no Chrome pela URL pública.
- JSON, SARIF, favicon, CSS e JavaScript foram servidos com sucesso.

## TLS e rede

- `http://3.149.250.106` redireciona para HTTPS.
- `https://3.149.250.106/health` retorna `{"status":"ok"}` com validação pública do certificado.
- Certificado de IP Let’s Encrypt short-lived emitido pelo Certbot 5.4.
- Timer systemd habilitado duas vezes ao dia; serviço de renovação terminou com status 0.
- `certbot renew --dry-run` concluiu a simulação com sucesso.

## Limites conhecidos

- A análise web é passiva: verifica transporte, headers e padrões no HTML/JavaScript retornado. Não explora, não altera o alvo e não substitui um pentest autorizado.
- O motor SAST analisa Python; suporte completo a outras linguagens não está implementado.
- Ausência de achados não garante ausência de vulnerabilidades.
- A sessão Codex é única por instalação e persiste no volume `codex_auth` até logout, revogação ou remoção do volume.

## Operação

Use `docker compose logs api worker codex` para diagnóstico. Não publique logs, `.env`, volumes ou dados da conta. Restrinja SSH/22 no Security Group para o IP administrativo `/32`.
