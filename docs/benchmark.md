# Avaliação reproduzível do detector

Execute `python -m scripts.benchmark --output reports/benchmark.json` com Python 3.12 e requirements.txt. Os 42 casos autorais em `benchmarks/corpus.json` nunca são executados; somente analisados. Os rótulos esperados usam pares (regra, linha). Cada par previsto corretamente conta como TP, achado inesperado como FP e esperado ausente como FN. Denominadores vazios são publicados como `null`.

Resultado medido durante desenvolvimento: **29 TP, 0 FP, 2 FN**; precisão **100%**, recall **93,55%**, F1 **96,67%**. São números deste corpus sintético pequeno, utilizado no desenvolvimento; não são uma estimativa de precisão em repositórios reais nem uma avaliação independente. Casos seguros são verificados sem transformar ausência de achados em prova de segurança.

| Limitação medida | Caso | Consequência |
| --- | --- | --- |
| Fluxo entre chamadas Python | `py-known-interprocedural` | Entrada retornada por uma função pode não alcançar o sink no modelo de taint. |
| Alias de importação JavaScript | `js-known-alias` | `exec` importado como `run` não é resolvido pelo detector estrutural. |

Os resultados por extensão, erros de parsing, achados inesperados e falhas de detecção estão no JSON. O CI mantém esses dois falsos negativos visíveis e falha se aparecerem erros, falsos positivos ou mais falsos negativos. Os testes de regressão cobrem separadamente comentários, strings, múltiplas ocorrências, redação de literais e falha fechada de parsing.

Para uma avaliação independente, separar um conjunto autorizado nunca usado para desenvolver regras, rotulá-lo manualmente e comparar com Bandit/Semgrep. Não apresentar os testes unitários como benchmark estatístico. A revisão de IA não muda os rótulos do benchmark nem o gate; avaliar sugestões de correção exige revisão humana e testes de comportamento.

`scripts/load_smoke.py`, executado dentro do container API, envia 12 análises com quatro clientes concorrentes, confirma gates e registra duração, p95 e workers online. É um teste limitado da fila e da replicação, não uma medição de capacidade máxima. Seus jobs sintéticos são removidos por UUID/projeto ao terminar.
