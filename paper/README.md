# O artigo

Quatro versões do mesmo trabalho. Só a primeira é escrita do zero; as
outras derivam dela e não podem contar números diferentes.

| Pasta | Versão | Páginas |
|---|---|---|
| [`IDS_P4/`](IDS_P4/) | completa, em inglês (`main.tex`): a versão de referência | 45 |
| [`IDS_P4_PT/`](IDS_P4_PT/) | curta, em português, IEEEtran | 7 |
| [`IDS_P4_CORINGA/`](IDS_P4_CORINGA/) | português, sem modelo de evento (`article`, uma coluna) | 12 |
| [`IDS_P4_SBRC/`](IDS_P4_SBRC/) | português, modelo da SBC, trilha principal do SBRC | 14 |

Cada pasta tem o `.tex`, o `.bib` e o PDF compilado.

## Como uma deriva da outra

    IDS_P4/main.tex  ->  IDS_P4_PT/artigo.tex  ->  IDS_P4_SBRC/artigo.tex
                                                ->  IDS_P4_CORINGA/artigo.tex

- A PT é reescrita à mão a partir do `main.tex`.
- A SBRC e a coringa não têm corpo próprio: o `montar.py` de cada uma copia
  o corpo da PT sem edição. A SBRC escreve só a primeira página (resumo e
  *abstract* de até 10 linhas); a coringa reaproveita esse resumo e esse
  *abstract*.
- Correção de texto se faz no `main.tex` e na PT; depois, `python montar.py`
  na SBRC e, em seguida, na coringa.

`python tests/check_manuscript_numbers.py` confere todo número do
`main.tex`, da PT e da SBRC contra os artefatos em `output/` e lista o que
não tiver artefato que o sustente.

Para compilar, numa cópia isolada para não deixar `.aux` e `.log` aqui:
`pdflatex`, `bibtex`, `pdflatex`, `pdflatex`. O README de cada pasta tem os
detalhes.

## Os documentos em `IDS_P4/`

Além do manuscrito, `IDS_P4/` guarda o registro de como cada afirmação foi
conferida. São registros congelados: não se reescrevem; uma correção entra
como documento novo que declara o que substitui. Os de 2026-09-09 descrevem
o manuscrito daquela data, e alguns números deles já foram substituídos.

**Achados e substituições (os mais importantes):**

| Documento | Assunto |
|---|---|
| `SERVICE_BASED_HEADER_FINDING.md` | regras baseadas em serviço: no Snort 3, porta e protocolo do cabeçalho não são condição necessária |
| `HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md` | troca do padrão do compilador para `snort3` (2026-10-05) e as medições refeitas no BMv2 |
| `SNORT3_MANUSCRIPT_AUDIT.md` | conferência dos três manuscritos depois da troca |
| `EXTERNAL_RULESETS_ROBUSTNESS.md` | o compilador em rulesets fora do avaliado |
| `PARSER_DOMAIN_RECONCILIATION.md` | domínio de pacotes do parser P4 e fail-open |
| `IR_CONTENT_NEGATION_SUPERSESSION.md`, `IR_CONTENT_WHITESPACE_SUPERSESSION.md` | duas correções na representação de `content` |

**Revisão pré-submissão e campanha:** `REVIEW_ITEMS_RESOLUTION_AUDIT.md` e
`CAMPAIGN_INTEGRATION_AUDIT.md`.

**Redação por seção (2026-09-09):** `ABSTRACT_WRITING_AUDIT.md`,
`INTRODUCTION_CONTRIBUTIONS_AUDIT.md`, `RELATED_WORK_REVISION_AUDIT.md`,
`METHODOLOGY_METRICS_AUDIT.md`, `RESULTS_WRITING_AUDIT.md`,
`DISCUSSION_WRITING_AUDIT.md`, `THREATS_WRITING_AUDIT.md`,
`CONCLUSION_WRITING_AUDIT.md`, `APPENDIX_PROFILE_AUDIT.md` e
`RQ_ALIGNMENT_AUDIT.md`.

**Fechamento, figuras e LaTeX (2026-09-09 a 2026-09-23):**
`FINAL_SCIENTIFIC_CLOSING_AUDIT.md`, `FINAL_STATIC_AUDIT.md`,
`FINAL_CHANGELOG.md`, `MANUSCRIPT_FACT_CHECK.md`, `LATEX_BUILD_AUDIT.md`,
`LATEX_LAYOUT_AUDIT.md`, `FIGURE_AUDIT.md` e `PIPELINE_FIGURE_AUDIT.md`.

**Substituído em parte:** a conclusão de "nenhuma lacuna de implementação"
do `SEMANTIC_SOUNDNESS_AUDIT.md`, anterior à discrepância do parser, foi
substituída pelo `FINAL_SCIENTIFIC_CLOSING_AUDIT.md`.
