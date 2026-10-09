"""Monta artigo.tex, versao coringa (sem modelo de evento), a partir das outras.

O corpo e copiado sem edicao de ../IDS_P4_PT/artigo.tex, e o abstract e o
resumo, sem edicao de ../IDS_P4_SBRC/artigo.tex, que ja tem os dois em
paralelo e conferidos pelo tests/check_manuscript_numbers.py. Aqui so ficam o
preambulo neutro (article, uma coluna) e o estilo da bibliografia. Correcao
de texto se faz no IDS_P4_PT (corpo) ou no montar.py do IDS_P4_SBRC (abstract
e resumo), e se propaga com:

    python montar.py
"""

from pathlib import Path
import shutil


RAIZ = Path(__file__).resolve().parent.parent
PT = RAIZ / "IDS_P4_PT" / "artigo.tex"
SBRC = RAIZ / "IDS_P4_SBRC" / "artigo.tex"
DESTINO = RAIZ / "IDS_P4_CORINGA"


def trecho(texto, inicio, fim):
    i = texto.index(inicio)
    return texto[i + len(inicio):texto.index(fim, i)].strip("\n")


pt = PT.read_text(encoding="utf-8")
corpo = pt[pt.index(r"\section{Introdução}"):pt.index(r"\bibliographystyle{IEEEtran}")]

sbrc = SBRC.read_text(encoding="utf-8")
abstract = trecho(sbrc, r"\begin{abstract}", r"\end{abstract}")
resumo = trecho(sbrc, r"\begin{resumo}", r"\end{resumo}")

PREAMBULO = r"""\documentclass[11pt,a4paper]{article}

\usepackage[T1]{fontenc}
\usepackage[utf8]{inputenc}
\usepackage[english,brazilian]{babel}
\usepackage{lmodern}
\usepackage[margin=2.5cm]{geometry}
\usepackage{amsmath}
\usepackage{booktabs}
\usepackage[hyphens]{url}
\usepackage{microtype}
\usepackage{cite}
\usepackage[font=small]{caption}
\captionsetup[table]{position=top,skip=6pt}

\newcommand{\cls}[1]{\textup{\textsc{#1}}}
\newcommand{\snortimpl}{\ensuremath{\mathrm{Snort}(r,p) \Rightarrow \mathrm{P4\_candidato}(r,p)}}

\title{Compilação de Cabeçalhos de Regras do Snort~3 em\\
Pré-filtros P4 Conservadores: Avaliação no BMv2}

\author{
Arthur de Freitas Medeiros\\
\small Universidade Federal do Pampa (UNIPAMPA), Alegrete, RS, Brasil\\
\small\texttt{arthurfreitas.aluno@unipampa.edu.br}
\and
Silvio E. Quincozes\\
\small Faculdade de Computação (FACOM), Universidade Federal de Uberlândia\\
\small Monte Carmelo, MG, Brasil\\
\small\texttt{sequincozes@ufu.br}
}

\date{Outubro de 2026}

\begin{document}

\maketitle

\begin{abstract}
""" + resumo + r"""
\end{abstract}

\begin{otherlanguage}{english}
\begin{abstract}
""" + abstract + r"""
\end{abstract}
\end{otherlanguage}

"""

FIM = r"""\bibliographystyle{plain}
\bibliography{references}

\end{document}
"""

DESTINO.mkdir(exist_ok=True)
(DESTINO / "artigo.tex").write_text(PREAMBULO + corpo + FIM, encoding="utf-8", newline="\n")
shutil.copy(RAIZ / "IDS_P4_PT" / "references.bib", DESTINO / "references.bib")
print("ok", len(corpo.splitlines()), "linhas de corpo")
