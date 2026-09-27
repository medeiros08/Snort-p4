#!/usr/bin/env python3
"""Teto do ganho dos achados de precisao de cabecalho ainda abertos.

A revisao de 2026-09-11 deixou abertos H12 (faixas de porta descartadas
embora a chave seja ternaria), M1 (`itype`/`icode` delegados) e M2
(`ip_proto` delegado). Este estagio nao os implementa: mede quantas regras
cada um poderia tirar do fallback do plano strong-discriminator congelado e,
dai, o maximo que a reducao sobre o ruleset inteiro poderia ganhar. O teto
supoe que cada regra retirada nunca seria candidata, entao nenhuma
implementacao ganharia mais.

    H12   NECESSARY com predicado de porta em FALLBACK por faixa (faixa
          isolada ou lista com faixa, sem negacao): a faixa vira prefixos
          ternarios
    M1    NECESSARY com `itype` ou `icode`
    M2    UNSUPPORTED com `ip_proto`: o campo de protocolo ja e chave

Codigos de saida:
    0   artefato gravado
    1   entrada ausente

Uso:
    python tests/analyze_header_precision_bounds.py
"""

from __future__ import annotations

import hashlib
import json
import sys

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFESTO = PROJECT_ROOT / "output" / "semantic_manifest.json"
PARTICAO = PROJECT_ROOT / "output" / "campaign" / "plano_strong_discriminator" / "particao.json"
EXPOSICAO = PROJECT_ROOT / "output" / "analysis" / "service_based_header_exposure.json"
SAIDA = PROJECT_ROOT / "output" / "analysis" / "header_precision_bounds.json"
RULESET = 4017


def prefixos(inicio: int, fim: int) -> int:
    """Numero de prefixos ternarios que cobrem exatamente [inicio, fim]."""

    total = 0
    while inicio <= fim:
        tamanho = 1
        while inicio % (tamanho * 2) == 0 and inicio + tamanho * 2 - 1 <= fim:
            tamanho *= 2
        total += 1
        inicio += tamanho
    return total


def termos_de_porta(valor) -> int | None:
    """Termos ternarios de uma expressao de porta; None se houver negacao ou variavel."""

    texto = str(valor).strip()
    itens = texto[1:-1].split(",") if texto.startswith("[") else [texto]
    total = 0
    for item in itens:
        item = item.strip()
        if item.startswith("!") or item.startswith("$"):
            return None
        if ":" in item:
            a, b = item.split(":")
            total += prefixos(int(a) if a else 0, int(b) if b else 65535)
        elif item.isdigit():
            total += 1
        else:
            return None
    return total


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def main() -> int:
    for caminho in (MANIFESTO, PARTICAO, EXPOSICAO):
        if not caminho.exists():
            print(f"entrada ausente: {caminho}", file=sys.stderr)
            return 1

    regras = json.loads(MANIFESTO.read_text(encoding="utf-8"))["rules"]
    elegiveis = {str(s) for s in json.loads(PARTICAO.read_text(encoding="utf-8"))["sids_no_prefilter"]}
    exposicao = json.loads(EXPOSICAO.read_text(encoding="utf-8"))
    service_based = set(exposicao["expostas"]["sids"]) | set(exposicao["expostas_por_servico_implicito"]["sids"])

    h12, termos, m1, m2 = [], {}, [], []
    for regra in regras:
        sid = str(regra["rule_id"])
        nomes = {o["name"] for o in regra["parsed_rule"]["options"]}
        if regra["classification"] == "NECESSARY":
            portas = [
                p for p in regra["fallback"]
                if p.get("kind") == "HEADER" and p.get("field") in ("src_port", "dst_port")
            ]
            if portas:
                contagens = [termos_de_porta(p["value"]) for p in portas]
                if all(c is not None for c in contagens):
                    h12.append(sid)
                    produto = 1
                    for c in contagens:
                        produto *= c
                    termos[sid] = produto
            if nomes & {"itype", "icode"}:
                m1.append(sid)
        elif regra["classification"] == "UNSUPPORTED" and "ip_proto" in nomes:
            m2.append(sid)

    def bloco(sids, fora):
        return {
            "regras": len(sids),
            "fora_do_strong": len(fora),
            "teto_pontos_sobre_ruleset": round(100.0 * len(fora) / RULESET, 4),
            "sids": sorted(sids, key=int),
        }

    relatorio = {
        "analise": "header_precision_bounds",
        "gerador": "tests/analyze_header_precision_bounds.py",
        "manifesto_sha256": _sha256(MANIFESTO),
        "particao_strong_sha256": _sha256(PARTICAO),
        "definicao": (
            "teto = regras que sairiam do fallback do plano strong congelado / 4017; "
            "supoe que nenhuma delas seria candidata"
        ),
        "h12_faixas_de_porta": {
            **bloco(h12, [s for s in h12 if s not in elegiveis]),
            "por_porta": len([s for s in h12 if s not in service_based]),
            "termos_ternarios_antes_de_dedup": sum(termos.values()),
        },
        "m1_itype_icode": bloco(m1, [s for s in m1 if s not in elegiveis]),
        "m2_ip_proto": bloco(m2, m2),
    }
    SAIDA.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for chave in ("h12_faixas_de_porta", "m1_itype_icode", "m2_ip_proto"):
        b = relatorio[chave]
        print(f"{chave:<22} regras {b['regras']:>4}  fora do strong {b['fora_do_strong']:>4}  "
              f"teto {b['teto_pontos_sobre_ruleset']:.2f} pontos")
    print(f"gravado em {SAIDA.relative_to(PROJECT_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
