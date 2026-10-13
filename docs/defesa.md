# Roteiro da defesa e plano até 20/10/2026

## Apresentação sugerida — 8 a 10 minutos

1. **Problema (1 min):** detectar falhas antes do deploy; explicar SAST e por que o código não precisa ser executado.
2. **Arquitetura (1 min):** mostrar C4, fila, banco, worker e integração Codex. Comparar modo Docker com modo local.
3. **AST e regras (2 min):** explicar como Call, Assign, nomes importados e literais geram violações. Mostrar que comentário contendo eval não dispara a regra.
4. **Taint (2 min):** exemplo request → term → query → cursor.execute. Mostrar arquivo, linha, CWE e rastro. Trocar pela consulta parametrizada e repetir.
5. **Codex (1 min):** login oficial, escolher achado e mostrar explicação/código sugerido. Explicar que a saída não foi executada e não altera o Gate. Se a conta estiver indisponível, mostrar o erro real; não apresentar resposta fictícia como evidência.
6. **DevSecOps (1 min):** abrir workflow, execução vermelha com vulnerabilidade, correção e execução verde. Mostrar a proteção da branch exigindo security-gates.
7. **Avaliação crítica (1 min):** resultados do benchmark, falsos positivos, falsos negativos, fronteiras de linguagem e escolha de IA externa.

## Distribuição sugerida para 4–5 integrantes

| Frente | Responsabilidade |
| --- | --- |
| Motor | AST, regras, taint, casos difíceis |
| Backend | API, banco, fila, limites e logs |
| IA | Login Codex, revisão, validação e avaliação semântica |
| DevSecOps | Docker, CI, testes e branch protection |
| Dashboard/documentação | Métricas, UX, roteiro e evidências; combinar outra frente se forem quatro integrantes |

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

Criar corpus autorizado com rótulo esperado por regra e posição. Separar conjuntos usados na implementação dos usados na avaliação. Contar TP, FP e FN por categoria, não apenas por arquivo. Calcular precision=TP/(TP+FP), recall=TP/(TP+FN) e F1. Definir tratamento de denominador zero. Os testes unitários existentes comprovam regressões pontuais; **não equivalem a um benchmark representativo de precisão**.

Comparar também o julgamento humano com possible_false_positive da IA e avaliar se o código proposto compila, preserva comportamento e remove a falha. A base não executa automaticamente correções produzidas pelo modelo.

## Pendências acadêmicas

O PDF cita parsing multilinguagem, mas também exige uma linguagem alvo escolhida no início. Esta versão implementa Python exclusivamente: apresentar essa decisão e confirmar o escopo cobrado. Tree-sitter, Java/JS, Semgrep e Ollama não estão implementados. A escolha Codex deve ser declarada, pois os dados são enviados a serviço externo e não há inferência local.
