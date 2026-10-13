# NULL//SENTRY — Security Operations Platform

Projeto Integrador FIAP. Linguagens suportadas: **Python, JavaScript, TypeScript, Java, PHP, Go, C# e Ruby**. IA escolhida: **Codex, com login oficial da conta ChatGPT no navegador**.

Plataforma de segurança com motor AST/taint profundo para Python, camada SAST multilanguage para sete famílias adicionais, inspeção passiva de sites públicos, FastAPI, dashboard, histórico, relatórios JSON/SARIF e Security Gates. Em Docker: PostgreSQL, Redis, Celery e serviço independente de integração Codex. Não é um scanner comercial nem uma garantia de ausência de falhas.

## Equipe

- Mateus dos Santos da Silva — 558436
- Nickolas Moreno Cardoso — 557132
- André Giovane de Maria — 556384

## Iniciar com Docker

Requisitos: Docker Desktop com Linux containers/Compose, acesso à internet para baixar imagens e dependências e uma conta com acesso ao Codex para revisão com IA.

~~~powershell
python scripts/init_env.py
docker compose up --build -d
~~~

Abra **http://localhost:8000**. Aguarde a construção dos containers. O código enviado é analisado como texto; nunca execute os exemplos vulneráveis.

1. Clique em **Carregar exemplo vulnerável** e **Executar análise estática**.
2. O resultado esperado são quatro achados: credencial, SQL injection, shell e execução dinâmica; Gate BLOCKED.
3. Clique em **Conectar Codex**, abra o endereço oficial e digite o código temporário. A senha é informada somente à OpenAI.
4. Depois da conexão, clique em **Revisar com Codex** em um achado. A revisão é opcional e explícita; envia contexto com literais ocultos.
5. Analise examples/safe.py com o mesmo nome de projeto: resultado esperado PASSED. Observe a tendência e exporte o JSON.

Para analisar uma página pública, selecione **Site público**, informe uma URL HTTP/HTTPS e aguarde o worker. A inspeção é passiva e limitada: verifica transporte, headers, formulários, conteúdo misto e padrões perigosos no HTML/JavaScript retornado, sem explorar ou alterar o alvo. Endereços privados, locais, reservados e portas diferentes de 80/443 são bloqueados. Os resultados podem ser baixados em JSON ou SARIF. O botão **PDF + Codex** solicita um resumo executivo à IA e gera um documento profissional com gate, prioridades, plano de ação e todos os achados.

O login por código pode precisar ser habilitado nas configurações de segurança da conta ou pelo administrador. Acesso, disponibilidade e limites dependem da conta. O sistema não reutiliza automaticamente a sessão deste aplicativo Codex. Uma sessão separada é criada no serviço do projeto.

O modelo é o padrão disponibilizado pelo Codex para a conta; nenhum nome de modelo é fixado. As credenciais ficam no volume codex_auth, gerenciadas pelo CLI, e não são retornadas ao dashboard. Use **Desconectar conta** ao terminar a demonstração. O serviço atende uma conta por instalação, não contas isoladas por visitante.

## Execução local sem Docker

~~~powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m uvicorn sast.api:app --host 127.0.0.1 --port 8000
~~~

Sem DATABASE_URL e REDIS_URL, usa SQLite local e processamento em background do FastAPI. Esse modo permite demonstrar o motor e a interface, mas **não demonstra Celery/PostgreSQL**. Para login e revisão, prefira o serviço Codex no Compose; sem a ponte, a interface informa integração indisponível.

## CLI e Security Gates

O CLI e os testes do motor usam apenas a biblioteca padrão de Python.

~~~powershell
python -m sast.cli examples/vulnerable.py --output reports/vulnerable.json
python -m sast.cli examples/safe.py --format sarif --output reports/safe.sarif
python -m sast.cli sast --output reports/self-scan.json
python -m unittest discover -s tests -v
node --test codex-bridge/rpc.test.mjs
~~~

Saídas do CLI: 0 = PASSED, 1 = BLOCKED, 2 = ERROR. HIGH/CRITICAL bloqueiam por padrão. Erros de parsing ou ausência de arquivos também impedem sucesso. --threshold altera o limiar. Erros de análise não são tratados como código seguro.

O workflow .github/workflows/security.yml executa testes, AST, Bandit, build Docker e smoke test de fila/banco. As fixtures vulneráveis ficam fora do escopo de varredura do produto, mas são verificadas pelos testes. Configure o job **security-gates** como obrigatório nas regras de proteção da branch do GitHub; o arquivo de workflow sozinho não impede merges.

## Componentes

| Diretório | Responsabilidade |
| --- | --- |
| sast/engine.py | AST, regras, fluxo de dados, contexto sem literais |
| sast/api.py | Recepção, validação, consultas, métricas, revisão |
| sast/jobs.py | Worker Celery e alternativa local |
| sast/storage.py | Repositório SQLite/PostgreSQL |
| sast/cli.py | Gate de CI e relatórios JSON/SARIF |
| sast/scanner.py / multilang.py | Orquestração e regras multilanguage |
| sast/site_scanner.py | Inspeção passiva de páginas públicas com proteção SSRF |
| sast/pdf_report.py | Relatório executivo PDF com resumo Codex |
| codex-bridge/ | App Server via JSON-RPC, login e revisão estruturada |
| web/ | Dashboard servido pela mesma origem |
| tests/ | Regressões de precisão, segurança e API |
| docs/ | Arquitetura, limitações, validação e defesa |

## Regras implementadas

| ID | Violação | CWE | Severidade |
| --- | --- | --- | --- |
| S001 | Literal em variável de credencial | 798 | HIGH |
| S002 | eval/exec | 95 | HIGH |
| S003 | Shell / subprocess com shell=True | 78 | HIGH |
| S004 | Entrada externa alcança consulta SQL | 89 | HIGH |
| S005 | SQL dinâmico com origem não confirmada | 89 | MEDIUM |
| S006 | Desserialização insegura | 502 | HIGH |
| S007 | MD5/SHA-1 | 327 | MEDIUM |
| S008 | verify=False | 295 | MEDIUM |
| S009 | Entrada externa em caminho de arquivo | 22 | HIGH |

A classificação é contextual e conservadora: MD5 pode ter uso não criptográfico; uma string chamada secret pode ser um exemplo; métodos chamados execute podem não ser SQL. A revisão humana e a confiança do achado ajudam a avaliar falsos positivos. Consulte os limites de fluxo em docs/arquitetura.md.

## Situação da validação

O deploy de produção foi validado em Ubuntu com Docker Compose: 45 testes passaram (37 Python + 8 Node), PostgreSQL, Redis e Celery processaram análises reais, e os gates vulnerável/seguro retornaram BLOCKED/PASSED. Uma URL pública também foi inspecionada de ponta a ponta pelo worker, com achados web persistidos e disponíveis para relatório JSON/SARIF/PDF. HTTPS público com certificado confiável, redirecionamento HTTP e renovação automática foram exercitados. A interface NULL//SENTRY, totalmente dark e inspirada em terminais de segurança, foi validada visualmente no Chrome pela URL pública.

As dependências diretas Python estão fixadas; transitivas e imagens ainda podem receber lock/digests para maior reprodutibilidade. O CLI Codex foi validado e fixado em `CODEX_VERSION=0.162.1` no ambiente de produção. O login oficial por device code, a conexão de uma conta ChatGPT e uma revisão real de achado foram concluídos com sucesso.

## Escopo acadêmico e escolhas

O enunciado recomenda LLM local (Ollama/Llama 3). Esta implementação usa Codex **conforme a escolha do projeto**, com inferência externa e dependência de conta/internet. Registrar essa alteração na defesa e confirmar sua aceitação com o professor é uma pendência acadêmica. Ollama não está implementado.

Python usa AST e taint analysis intraprocedural. JavaScript, TypeScript, Java, PHP, Go, C# e Ruby usam regras conservadoras por padrões e contexto, com menor profundidade semântica; cada achado informa a engine utilizada. Análise entre arquivos e Tree-sitter ainda não estão implementados. Bandit complementa o CI; os achados do dashboard vêm do motor próprio.

Use apenas código de autoria do grupo ou autorizado. O PDF fornecido foi consultado como referência e não deve ser publicado no repositório: está ignorado no Git.

## Referências técnicas

- [Codex App Server: protocolo e autenticação](https://learn.chatgpt.com/docs/app-server)
- [Autenticação Codex e login por código](https://learn.chatgpt.com/docs/auth)
- [Configuração Codex](https://learn.chatgpt.com/docs/config-file/config-reference)
- [FastAPI em containers](https://fastapi.tiangolo.com/deployment/docker/)
- [Celery: arquitetura e execução](https://docs.celeryq.dev/en/stable/getting-started/introduction.html)

## Publicação no servidor

A configuração de produção publica somente o proxy nas portas 80/443. O endereço esperado é **https://3.149.250.106**. O Nginx redireciona HTTP para HTTPS e o Certbot 5.4 solicita um certificado gratuito de IP, perfil shortlived, ao Let’s Encrypt. O timer systemd verifica a renovação duas vezes ao dia e recarrega o Nginx após renovar.

No servidor, o projeto deve ficar em /opt/sentinela-sast. Depois execute python3 scripts/init_env.py e sudo sh deploy/install-production.sh. As portas TCP 22, 80 e 443 precisam estar liberadas no Security Group.
