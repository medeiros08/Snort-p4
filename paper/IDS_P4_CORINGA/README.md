# Versão coringa (sem modelo de evento)

`artigo.tex` é a versão em português sem modelo de evento nenhum: classe
`article`, 11 pt, A4, uma coluna, com resumo e *abstract* na primeira
página. Serve para circular o texto (por exemplo, para o coautor) sem
amarrá-lo a um evento. Dá 12 páginas com as referências.

Nada aqui é escrito à mão. O `montar.py` junta:

- o corpo de `../IDS_P4_PT/artigo.tex`, sem edição;
- o resumo e o *abstract* de `../IDS_P4_SBRC/artigo.tex`, sem edição (os
  dois em paralelo, já conferidos por `tests/check_manuscript_numbers.py`);
- o preâmbulo neutro e a bibliografia em estilo `plain`, que são desta pasta.

Cadeia: `main.tex` → `IDS_P4_PT` → (`IDS_P4_SBRC`, `IDS_P4_CORINGA`).
Correção de texto se faz no `IDS_P4_PT` (corpo) ou no `montar.py` do
`IDS_P4_SBRC` (resumo e *abstract*); depois:

    python ../IDS_P4_SBRC/montar.py
    python montar.py

`references.bib` é cópia de `../IDS_P4_PT/references.bib`, para a pasta
subir inteira no Overleaf.

Compilar numa cópia isolada, como as outras versões (MiKTeX, sem `latexmk`):

    pdflatex --enable-installer artigo
    bibtex artigo
    pdflatex --enable-installer artigo
    pdflatex --enable-installer artigo

Estado em 2026-10-09: 12 páginas, zero erro, zero overfull e zero underfull.
