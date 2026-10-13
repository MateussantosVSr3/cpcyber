# Arquitetura técnica

## C4 — contexto

~~~mermaid
flowchart LR
    Dev[Integrante / Desenvolvedor] -->|Código Python autorizado| SAST[Sentinela SAST]
    SAST -->|Achados, CWE, Gate e tendência| Dev
    Dev -->|Login no navegador| OpenAI[OpenAI / Conta Codex]
    SAST -->|Revisão solicitada pelo usuário| OpenAI
    CI[GitHub Actions] -->|Varredura e gates| Engine[CLI Sentinela + Bandit]
~~~

## C4 — containers

~~~mermaid
flowchart LR
    UI[Dashboard HTML/CSS/JS] -->|HTTP mesma origem| API[FastAPI :8000]
    API --> DB[(PostgreSQL)]
    API -->|ID da análise| Redis[(Redis / broker)]
    Redis --> Worker[Celery / Python AST]
    Worker --> DB
    API -->|Bearer interno| Bridge[Serviço Node Codex]
    Bridge -->|JSON-RPC por stdio| Codex[Codex App Server]
    Codex -->|OAuth e inferência| OpenAI[OpenAI]
    Codex --> Auth[(Volume de sessão)]
~~~

## Fluxo de análise

1. A API valida até 100 caminhos relativos .py, até 100 KB por arquivo e 1 MB total. O corpo HTTP tem limite adicional de 2 MB.
2. Persiste uma análise QUEUED e o texto, usando UUID. O broker recebe somente o ID.
3. O worker lê a análise e marca RUNNING. O parser não importa módulos do código submetido.
4. O motor gera achados por arquivo/linha/regra, CWE, confiança, rastreio e contexto com literais string/bytes ocultos.
5. Grava COMPLETED e remove o código original da linha do banco. Falha operacional gera FAILED/ERROR.
6. O dashboard consulta estado e métricas. Cada análise continua no histórico; cartões usam a última análise concluída por projeto entre as últimas 100.
7. A revisão Codex é solicitada por achado; a resposta validada fica separada da severidade determinística. Não aplica patches e não executa testes automaticamente.

O corpo da revisão é tratado como dado não confiável. O serviço inicia uma thread efêmera com sandbox de leitura e shell/web/multiagentes desativados. Solicitações de ferramentas originadas no protocolo são recusadas. A ponte recebe só o achado, não o diretório do usuário nem seu repositório. A saída é validada contra um formato restrito.

## Taint analysis

Análise **intraprocedural, sensível à ordem de atribuições e conservadora nos ramos**. Fontes: input e padrões request/flask.request. Propagação: variáveis locais, expressões, f-strings, concatenação, atribuição aumentada e união de caminhos condicionais. Reatribuição limpa a marca; int/float removem a marca de injeção. Laços usam união iterativa, limitada a 64 rodadas. SQL parametrizado mantém consulta e parâmetros separados, sem classificar o valor de um parâmetro como SQL executável.

Não é interpretação completa de Python: não acompanha retorno de funções entre chamadas, importação entre arquivos, aliases redefinidos complexos, heap/objetos, todos os frameworks, comprehensions com escopo próprio, await assíncrono de todos os tipos, match/case ou todos os sanitizadores. Não há grafo de chamadas ou prova de alcançabilidade. Tratamento de exceções é conservador. Funções locais são inspecionadas mesmo se não forem chamadas. SQL dinâmico em variável intermediária sem fonte reconhecida pode passar sem S005. Essas limitações devem entrar no benchmark e na defesa.

## Escalabilidade e confiabilidade

API, worker e integração Codex são processos independentes. O worker pode ser replicado com docker compose up -d --scale worker=3. O broker usa persistência AOF; banco e sessão usam volumes. Fila usa JSON, prefetch=1 e confirmação tardia. Jobs concluídos não são reanalisados numa redelivery. O modo local de background é apenas demonstrativo e perde tarefas em trânsito ao encerrar o processo.

O sistema não implementa outbox transacional, dead-letter queue, deduplicação forte entre workers concorrentes, recuperação de todos os RUNNING após hard timeout ou migrações versionadas de banco. Se um job ficar preso, consultar logs e reenviar. Essas são melhorias necessárias para produção. A ponte aceita uma revisão por vez e rejeita concorrentes para limitar consumo da conta; revisões não usam a fila de varredura nesta versão.

## Fronteiras de segurança

Instalação local para um operador confiável. Só a API é publicada, vinculada a 127.0.0.1. PostgreSQL, Redis e ponte ficam na rede interna do Compose. Mutação via navegador exige mesma origem e cabeçalho personalizado; TrustedHost reduz exposição por Host inesperado. Isso não substitui autenticação de usuários. Não publicar em rede aberta sem implementar usuários, isolamento de sessões Codex, autorização por projeto, TLS, rate limiting e limites de armazenamento.

Nenhum upload é gravado como executável nem extraído de ZIP. Tokens permanecem no volume do Codex, não no JavaScript. O segredo do serviço é gerado aleatoriamente. A sessão pertence ao operador; esta aplicação não implementa OAuth multiusuário nem compartilhamento público de uma conta.

Literais são ocultos no contexto exibido e enviado à IA, mas nomes de variáveis/arquivos e metadados continuam visíveis. Código original fica temporariamente no banco durante a análise; backups/WAL podem reter dados mesmo após remoção lógica. Não afirmar anonimização completa nem eliminação criptográfica.

## Decisões

- Python AST: atende a escolha inicial de linguagem e permite explicar o algoritmo durante a defesa.
- Regras próprias + Bandit em CI: evidencia implementação autoral sem abandonar uma ferramenta consolidada.
- Codex App Server: permite login oficial na hora, como solicitado, e revisão estruturada. É alteração em relação ao LLM local sugerido.
- Gate determinístico: a IA não pode liberar automaticamente um achado de alta severidade.
- Dashboard sem dependências externas: nenhum CDN obrigatório; dados vêm da API e não de indicadores fictícios.
