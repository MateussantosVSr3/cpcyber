# Roteiro da defesa e plano até 20/10/2026

## Apresentação sugerida — 8 a 10 minutos

1. **Problema (1 min):** detectar falhas antes do deploy; explicar SAST e por que o código não precisa ser executado.
2. **Arquitetura (1 min):** mostrar C4, fila, banco, worker e integração Codex. Comparar modo Docker com modo local.
3. **AST e regras (2 min):** comparar Python AST e Tree-sitter em JavaScript/Java. Mostrar chamada real detectada, comentário ignorado e sintaxe inválida retornando ERROR. Identificar o parser no JSON.
4. **Taint (2 min):** exemplo request → term → query → cursor.execute. Mostrar arquivo, linha, CWE e rastro. Trocar pela consulta parametrizada e repetir.
5. **Codex (1 min):** login oficial, escolher achado e mostrar explicação/código sugerido. Explicar que a saída não foi executada e não altera o Gate. Se a conta estiver indisponível, mostrar o erro real; não apresentar resposta fictícia como evidência.
6. **DevSecOps (1 min):** abrir workflow, execução vermelha com vulnerabilidade, correção e execução verde. Mostrar a proteção da branch exigindo security-gates.
7. **Avaliação crítica (1 min):** resultados do benchmark, falsos positivos, falsos negativos, fronteiras de linguagem e escolha de IA externa.

## Equipe e divisão sugerida

| Frente | Responsabilidade |
| --- | --- |
| Mateus dos Santos da Silva — 558436 | Arquitetura, deploy, autenticação e DevSecOps |
| Nickolas Moreno Cardoso — 557132 | Parsers, regras, taint e benchmark |
| André Giovane de Maria — 556384 | Integração IA, dashboard, relatórios e documentação |

Esta divisão é uma sugestão para o ensaio, não uma declaração de autoria individual do trabalho realizado. O enunciado menciona 4–5 integrantes; confirmar a aceitação da equipe de três com o professor.

## Calendário de trabalho

| Data | Entrega verificável |
| --- | --- |
| 13–14/10 | Rodar a base, dividir frentes e confirmar com professor a substituição de LLM local por Codex |
| 15/10 | Ampliar corpus de detecção com casos vulneráveis e seguros revisados pelo grupo |
| 16/10 | Validar Docker/PostgreSQL/Celery, login real e pelo menos cinco revisões Codex |
| 17/10 | Pipeline no GitHub, Security Gate obrigatório e evidência de bloqueio/correção |
| 18/10 | Revisar dashboard, testes, limites e documentação; fixar versões validadas |
| 19/10 | Ensaiar defesa e gravar demonstração de contingência |
| 20/10 | Conferência final e envio antes de 23:59; reservar margem para problemas de upload |

## Medir precisão sem inventar números

Executar `python -m scripts.benchmark`. O corpus autoral contém 42 casos: 29 TP, 0 FP e 2 FN na validação de desenvolvimento. Explicar a diferença entre precisão e recall, mostrar os dois casos perdidos e a falta de independência do corpus. Denominadores vazios retornam null. Ver `docs/benchmark.md`. Os testes unitários comprovam regressões pontuais; **não equivalem a um benchmark representativo de precisão**.

Comparar também o julgamento humano com possible_false_positive da IA e avaliar se o código proposto compila, preserva comportamento e remove a falha. A base não executa automaticamente correções produzidas pelo modelo.

## Pendências acadêmicas

Python foi a linguagem inicial. A versão atual também faz parsing Tree-sitter em JavaScript, TypeScript, Java, PHP, Go, C# e Ruby. Explicar que as regras estruturais adicionais não têm a mesma análise de fluxo de Python. Semgrep não é uma dependência do projeto; a stack do PDF lista ferramentas recomendadas, não a obrigação de usar todas simultaneamente.

O CP2 exige LLM local; por decisão explícita do responsável o projeto mantém Codex externo. Não apresentar isso como cumprimento literal do requisito local. Declarar envio de contexto sanitizado ao provedor, dependência de conta/internet e limites de uso. A aceitação dessa substituição e do número de integrantes depende do professor.

## Perguntas para ensaio

- Por que SAST não executa o código recebido? Demonstrar parsing de um exemplo vulnerável sem importar o arquivo.
- O que significa zero achados? Nenhuma regra disparou; não garante ausência de vulnerabilidades.
- Como a IA influencia o bloqueio? Sugere severidade e remediação; o gate determinístico permanece preservado.
- Como demonstrar escalabilidade? Mostrar API/fila/worker separados, teste de fila e replicação; não prometer alta disponibilidade numa única VPS.
- Como comprovar CI? Abrir as execuções reais e a regra da branch. Não confundir arquivo YAML com pipeline executado.
- Como proteger o acesso? Login, hash scrypt, cookie seguro, sessão revogável, API interna e TLS. Nunca mostrar `.env`, chave SSH ou tokens na apresentação.
