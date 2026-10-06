# Versão SBRC (modelo SBC)

`artigo.tex` é a versão para o SBRC, em português, no modelo de artigos da
SBC. O corpo é o de `../IDS_P4_PT/artigo.tex`, copiado por `montar.py` sem
edição de texto. Só a primeira página (título, autores, *abstract* e resumo)
e o estilo da bibliografia são desta versão e ficam no `montar.py`.

A cadeia de derivação é `paper/IDS_P4/main.tex` → `IDS_P4_PT/artigo.tex` →
esta pasta. Correção de texto se faz no `IDS_P4_PT` e se propaga com:

    python montar.py

O `montar.py` só troca `~\cite` por ` \cite`, porque o rótulo autor-ano é
longo e o til o prendia na palavra anterior.

## Modelo

`sbc-template.sty` e `sbc.bst` vêm, sem alteração, do modelo oficial da SBC:

- arquivo `modelosparapublicaodeartigos.zip`, 542.902 bytes
- origem: https://www.sbc.org.br/wp-content/uploads/2024/07/modelosparapublicaodeartigos.zip
  (página Documentos → Templates para artigos e capítulos de livros)
- sha256 `2c4524a43fa1a6cc20b2f444448bb74ba42a3d33d56e9c8a4aba4654fdc6731a`
- baixado em 2026-10-05

O `.tex` de exemplo do modelo carrega `inputenc` duas vezes (utf8 e latin1);
aqui fica só `utf8`.

## Regras do evento

Chamada da trilha principal do SBRC 2026 (a de 2027 ainda não saiu):

- no máximo 14 páginas, contando resumo, figuras e referências;
- modelo da SBC;
- português ou inglês, com *abstract* e resumo de até 10 linhas cada na
  primeira página quando o artigo é em português;
- PDF pelo JEMS 3;
- a revisão não é anônima.

Confira na chamada de 2027 quando ela sair.

## Compilar

Numa cópia isolada, como as outras versões (MiKTeX, sem `latexmk`):

    pdflatex --enable-installer artigo
    bibtex artigo
    pdflatex --enable-installer artigo
    pdflatex --enable-installer artigo

Estado em 2026-10-06, depois de o texto passar a relatar a compilação
`snort3` (`paper/IDS_P4/HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md`): 14 páginas
com as referências, sem caixa estourada; *abstract* e resumo com 10 linhas
cada. Restam dois `Underfull \hbox` de espaçamento entre palavras (parágrafos
"Contexto mais amplo" e "Resolução de variáveis") e três `Underfull \vbox`,
nas páginas 7, 9 e 12, do `\flushbottom` do modelo.
