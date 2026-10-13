# Validação de produção — 13/10/2026

## Resultado

- 49 testes Python aprovados no container Python 3.12 (incluindo autenticação, parsers e métricas).
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
- JSON, SARIF, PDF executivo com Codex, favicon, CSS e JavaScript foram servidos com sucesso.

## TLS e rede

- `http://3.149.250.106` redireciona para HTTPS.
- `https://3.149.250.106/health` retorna `{"status":"ok"}` com validação pública do certificado.
- Certificado de IP Let’s Encrypt short-lived emitido pelo Certbot 5.4.
- Timer systemd habilitado duas vezes ao dia; serviço de renovação terminou com status 0.
- `certbot renew --dry-run` concluiu a simulação com sucesso.

## Limites conhecidos

- A análise web é passiva: verifica transporte, headers e padrões no HTML/JavaScript retornado. Não explora, não altera o alvo e não substitui um pentest autorizado.
- Python usa AST/taint. JavaScript, TypeScript, Java, PHP, Go, C# e Ruby usam parsing Tree-sitter e regras estruturais; sintaxe inválida gera ERROR. A profundidade de fluxo é menor que em Python e o parser é identificado por arquivo.
- Ausência de achados não garante ausência de vulnerabilidades.
- A sessão Codex é única por instalação e persiste no volume `codex_auth` até logout, revogação ou remoção do volume.

## Operação

Use `docker compose logs api worker codex` para diagnóstico. Não publique logs, `.env`, volumes ou dados da conta. O operador optou por manter SSH/22 aberto; HTTP/80 e HTTPS/443 também permanecem públicos. Os demais serviços não publicam portas.

## Atualização: autenticação e avaliação

- Login real na URL pública retornou 200; cookie com Secure, HttpOnly e SameSite=Strict.
- API sem autenticação retornou 401. Logout revogou a sessão.
- Chrome: login, dashboard e logout concluídos; nenhum erro JavaScript e nenhum overflow horizontal da página em 1440px ou 390px. Tabelas têm rolagem própria em telas pequenas.
- Conta Codex continuou conectada (ChatGPT Plus), sem reiniciar seu volume de sessão.
- Benchmark sintético de 42 casos: 29 TP, 0 FP, 2 FN, precisão 100%, recall 93,55%, F1 96,67%. Consulte as limitações em `benchmark.md`.
- Teste de fila com um worker: 12/12 análises corretas, quatro clientes concorrentes, p95 de 0,694 s.
- Replicação: dois workers responderam; 12/12 análises corretas, quatro clientes concorrentes, p95 de 0,790 s. A instalação voltou a um worker para poupar RAM. Estes números não demonstram capacidade máxima nem alta disponibilidade.
- O smoke agora aguarda a prontidão real do Celery antes de testar a fila. A primeira execução de CI identificou essa corrida de inicialização, que foi corrigida.
- Aceitação externa autenticada: projeto com oito linguagens vulneráveis retornou BLOCKED (oito achados); projeto seguro nas oito linguagens retornou PASSED; JavaScript inválido retornou ERROR. Os resultados identificaram Python AST e as sete gramáticas Tree-sitter.
- Downloads PDF dos três resultados retornaram documentos válidos; CSS, JavaScript e favicon carregaram sob sessão. Logout voltou a bloquear a API com 401.
- CI da base corrigida aprovado: https://github.com/MateussantosVSr3/cpcyber/actions/runs/38465752860. Evidência de PR vulnerável e proteção da branch em `pipeline.md`.
- Empacotamento via `git archive` preserva os arquivos versionados e os scripts LF. A unidade TLS invoca `/bin/sh` explicitamente para não depender do bit executável após extrações; permissões executáveis dos scripts também são versionadas.
