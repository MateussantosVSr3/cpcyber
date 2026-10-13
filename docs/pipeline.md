# Evidência do Security Gate em GitHub Actions

Repositório: https://github.com/MateussantosVSr3/cpcyber

## Demonstração controlada

O [PR #1](https://github.com/MateussantosVSr3/cpcyber/pull/1) introduziu, somente na branch de validação, um arquivo sintético com `eval(input())`. O arquivo foi analisado como texto e nunca executado nem enviado à VPS.

A [execução vulnerável](https://github.com/MateussantosVSr3/cpcyber/actions/runs/38465764514) detectou S002/HIGH no gate do motor, publicou SARIF e terminou com código 1. Com a proteção da branch aplicada, a API do GitHub retornou `mergeable_state: blocked` para esse PR. Isso comprova bloqueio de integração, além do comportamento do CLI.

O exemplo vulnerável foi removido na revisão seguinte. As execuções e respectivos commits permanecem no histórico do PR. A alteração final inclui a documentação desta evidência e melhorias no ciclo de inicialização/limpeza do CI.

A [execução da base corrigida](https://github.com/MateussantosVSr3/cpcyber/actions/runs/38465752860) concluiu com sucesso todos os testes, gates, build e smoke de PostgreSQL/Redis/Celery. O PR de validação só pode ser integrado depois de seu próprio check verde.

## Proteção da branch principal

- Pull request obrigatório para alterar `main`, inclusive para administradores.
- Check `security-gates` obrigatório, associado ao aplicativo GitHub Actions (15368).
- Branch deve estar atualizada em relação à base.
- Force push e exclusão da branch desabilitados.
- Nenhuma aprovação humana adicional obrigatória nesta configuração de grupo; o check automatizado é obrigatório.

O pipeline executa testes Python/Node, benchmark rotulado, contrato 0/1/2 do gate, varredura do diretório `sast`, Bandit de severidade alta em `sast`/`scripts`, build Docker e teste HTTP/PostgreSQL/Redis/Celery. Fixtures vulneráveis em `examples`, `tests` e `benchmarks` são exercitadas por testes, não tratadas como código de produção. O artefato `security-reports` contém resultados JSON/SARIF e benchmark.

O CI não contém credenciais de produção e não faz login no Codex. A implantação na VPS é um procedimento separado; um teste que falha não publica código no servidor. Consulte `validacao.md` para evidências de produção.
