"""Monta artigo.tex (modelo SBC, SBRC) a partir do corpo de ../IDS_P4_PT/artigo.tex.

O corpo e copiado sem edicao de texto; so a primeira pagina (titulo,
autores, abstract e resumo) e o estilo da bibliografia sao desta versao e
ficam aqui. Correcao de texto se faz no IDS_P4_PT e se propaga com:

    python montar.py
"""
from pathlib import Path
import shutil

RAIZ = Path(__file__).resolve().parent.parent
ORIGEM = RAIZ / "IDS_P4_PT" / "artigo.tex"
DESTINO = RAIZ / "IDS_P4_SBRC"

texto = ORIGEM.read_text(encoding="utf-8")
inicio = texto.index(r"\section{Introdução}")
fim = texto.index(r"\bibliographystyle{IEEEtran}")
corpo = texto[inicio:fim]
# Citacao autor-ano e longa; o til prende o rotulo inteiro na palavra anterior.
corpo = corpo.replace(r"~\cite{", r" \cite{")

PREAMBULO = r"""\documentclass[12pt]{article}

\usepackage{sbc-template}
\usepackage[T1]{fontenc}
\usepackage[utf8]{inputenc}
\usepackage[brazilian]{babel}
\usepackage{amsmath}
\usepackage{booktabs}
\usepackage{graphicx}
\usepackage[hyphens]{url}
\usepackage{microtype}

\sloppy

\newcommand{\cls}[1]{\textup{\textsc{#1}}}
\newcommand{\snortimpl}{\ensuremath{\mathrm{Snort}(r,p) \Rightarrow \mathrm{P4\_candidato}(r,p)}}

\title{Compilação de Cabeçalhos de Regras do Snort~3 em\\
Pré-filtros P4 Conservadores: Avaliação no BMv2}

\author{Arthur de Freitas Medeiros\inst{1}, Silvio E. Quincozes\inst{2}}

\address{Universidade Federal do Pampa (UNIPAMPA) -- Alegrete, RS -- Brasil
\nextinstitute
  Faculdade de Computação (FACOM) -- Universidade Federal de Uberlândia (UFU)\\
  Monte Carmelo, MG -- Brasil
  \email{arthurfreitas.aluno@unipampa.edu.br, sequincozes@ufu.br}
}

\begin{document}

\maketitle

\begin{abstract}
Programmable data planes can evaluate packet predicates before a software
IDS, but Snort~3 rules also depend on payload, flow and service semantics
that a P4 target cannot represent. We present a Snort-to-P4 compiler that
classifies each rule's relation to its predicate as \cls{Exact},
\cls{Necessary} or \cls{Unsupported} and records every omitted component.
For 2,931 service-based rules it keeps only the header addresses, since
Snort~3 skips their ports and protocol. Of 4,017 rules, 3,996 are necessary
and 21 unsupported; the backend installs 235 entries on BMv2. The global
prefilter marks 100\% of eligible packets in three CICIDS2017 traces,
observed alerts are preserved, and a 1,000-rule campaign with Snort as oracle
finds no violation. Provenance reduces the candidate rule set by only 18.3\%
of the ruleset, against 81.8\% under an earlier compilation that kept the
ports.
\end{abstract}

\begin{resumo}
Planos de dados programáveis podem avaliar predicados de pacote antes de um
IDS em software, mas as regras do Snort~3 dependem de payload, fluxo e
serviço, que um alvo P4 não representa. Apresentamos um compilador
Snort-para-P4 que classifica a relação de cada regra com seu predicado como
\cls{Exact}, \cls{Necessary} ou \cls{Unsupported} e registra tudo o que
omite. Em 2.931 regras baseadas em serviço, mantém só os endereços, pois o
Snort~3 não checa porta e protocolo delas. Das 4.017
regras, 3.996 são necessárias e 21 não suportadas; o backend instala 235
entradas no BMv2. O pré-filtro global marca 100\% dos pacotes elegíveis em
três traces do CICIDS2017, os alertas observados são preservados e uma
campanha com 1.000 regras, com o Snort como oráculo, não encontra violação.
A proveniência reduz as regras candidatas em só 18,3\% do ruleset, contra
81,8\% numa compilação anterior que mantinha as portas.
\end{resumo}

"""

FIM = r"""\bibliographystyle{sbc}
\bibliography{references}

\end{document}
"""

DESTINO.mkdir(exist_ok=True)
(DESTINO / "artigo.tex").write_text(PREAMBULO + corpo + FIM, encoding="utf-8")
shutil.copy(RAIZ / "IDS_P4_PT" / "references.bib", DESTINO / "references.bib")
print("ok", len(corpo.splitlines()), "linhas de corpo")
