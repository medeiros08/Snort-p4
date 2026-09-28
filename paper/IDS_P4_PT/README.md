# Versão curta em português

`artigo.tex` é a versão curta do artigo, em português e no formato IEEEtran
(conference), com coautoria de Silvio E. Quincozes (FACOM/UFU). É derivada de
`paper/IDS_P4/main.tex`, que continua sendo a fonte de verdade: todo número
daqui tem de bater com o `main.tex` e, por ele, com os artefatos em `output/`.
Mudou um número ou uma afirmação no `main.tex`, esta versão precisa mudar
também.

`references.bib` é cópia idêntica de `paper/IDS_P4/references.bib`, mantida
aqui para que a pasta suba inteira no Overleaf.

Compilar numa cópia isolada, como o `main.tex` (MiKTeX, sem `latexmk`):

    pdflatex --enable-installer artigo
    bibtex artigo
    pdflatex --enable-installer artigo
    pdflatex --enable-installer artigo

Estado em 2026-09-28: 7 páginas com referências, zero overfull/underfull.
Pendente de confirmação: afiliação do primeiro autor (o modelo trazia
FACOM/UFU; o texto usa UNIPAMPA, como o `main.tex`), título e limite de
páginas do evento.
