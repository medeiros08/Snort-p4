#!/usr/bin/env python3
"""Confere os numeros dos tres manuscritos contra os artefatos.

Dois passos:

    fatos      cada valor que os manuscritos citam e recalculado aqui a
               partir do artefato que o sustenta (manifestos, plano, metricas
               de trace, replays, campanhas, auditorias). Um fato e um nome,
               um valor e o caminho de onde veio
    varredura  todo numero dos tres .tex (corpo, legendas, tabelas, resumo)
               e normalizado (4,017 / 4.017; 92.298 / 92,298) e procurado
               entre os fatos, nas formas com e sem arredondamento. O que nao
               casa com nenhum fato nem com a lista de numeros estruturais
               (versoes, anos, portas do perfil, rotulos de secao) e listado
               para revisao manual

O passo de varredura nao prova que um numero esta no lugar certo, so que
existe um artefato com aquele valor; a correspondencia afirmacao a afirmacao
fica para a leitura. O que ele pega e numero digitado errado, valor que
sobrou da compilacao anterior sem estar marcado como tal e arredondamento
divergente entre versoes.

Grava output/analysis/manuscript_number_audit.json. Sai com 1 se houver
numero sem fato.

Uso:
    python tests/check_manuscript_numbers.py
"""

from __future__ import annotations

import json
import re
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT = PROJECT_ROOT / "output"
AN = OUT / "analysis"
CAMP = OUT / "campaign"
LEGADO = OUT / "historical" / "legacy_header_semantics"
SAIDA = AN / "manuscript_number_audit.json"

MANUSCRITOS = {
    "IDS_P4": (PROJECT_ROOT / "paper" / "IDS_P4" / "main.tex", "en"),
    "IDS_P4_PT": (PROJECT_ROOT / "paper" / "IDS_P4_PT" / "artigo.tex", "pt"),
    "IDS_P4_SBRC": (PROJECT_ROOT / "paper" / "IDS_P4_SBRC" / "artigo.tex", "pt"),
}

# Numeros que nao sao resultado: versoes, anos, portas e prefixos do perfil,
# valores de exemplo do texto, rotulos e larguras de layout.
ESTRUTURAIS = {
    "3.12.2.0", "1.2.4.2", "1.15.0", "22.04", "3.10", "2.9.15.1", "16", "9559",
    "65535", "20", "192.168.10.0", "24", "10.0.0.2", "80", "8080", "110", "143",
    "5060", "5061", "22", "21", "1521", "25", "53", "443", "18080", "255.255.255.255",
    "8", "4", "5", "1999", "2017", "2019", "2021", "2022", "2023", "2024", "2025",
    "2026", "1001", "100", "32", "48", "10", "11", "12", "13", "14", "15", "17",
    "18", "19", "9", "6", "7", "3", "2", "1", "0",
    # layout, enderecos e identificadores de build citados no ambiente
    "0.95", "127.0.0.1", "624", "68", "256",
}


def carregar(caminho: Path):
    return json.loads(caminho.read_text(encoding="utf-8"))


def jsonl(caminho: Path) -> list[dict]:
    return [json.loads(l) for l in caminho.read_text(encoding="utf-8").splitlines() if l.strip()]


class Fatos:
    def __init__(self):
        self.itens: list[dict] = []

    def add(self, nome: str, valor, fonte: Path | str):
        self.itens.append({"nome": nome, "valor": valor, "fonte": str(fonte).replace(str(PROJECT_ROOT), "").lstrip("\\/")})

    def valores(self) -> set[str]:
        """Formas aceitas de cada valor: exato e arredondado a 2, 1 e 0 casas."""

        formas = set()
        for item in self.itens:
            v = item["valor"]
            if isinstance(v, bool):
                continue
            if isinstance(v, int):
                formas.add(str(v))
            elif isinstance(v, float):
                for casas in (3, 2, 1, 0):
                    texto = f"{v:.{casas}f}"
                    formas.add(texto)
                    if casas and texto.endswith("0"):
                        formas.add(texto.rstrip("0").rstrip("."))
                # truncamento de faixa, p.ex. 92.2--94.9 a partir de 92.17 e 94.88
                formas.add(f"{int(v * 10) / 10:.1f}")
            else:
                formas.add(str(v))
        return formas


def pct(a: float, b: float) -> float:
    return 100.0 * a / b


def coletar() -> Fatos:
    f = Fatos()

    # Manifestos
    for nome, base in (("snort3", OUT), ("legacy", LEGADO)):
        man = carregar(base / "semantic_manifest.json")
        cls = man["summary"]["classification"]
        for k, v in cls.items():
            f.add(f"{nome}.{k}", v, base / "semantic_manifest.json")
        f.add(f"{nome}.cobertura_pct", pct(cls["NECESSARY"], 4017), base / "semantic_manifest.json")
        f.add(f"{nome}.regras", sum(cls.values()), base / "semantic_manifest.json")
        cont = Counter()
        for r in man["rules"]:
            for k in ("preserved", "delegated", "expanded", "fallback", "unassessed"):
                cont[k] += len(r[k])
        for k, v in cont.items():
            f.add(f"{nome}.predicados.{k}", v, base / "semantic_manifest.json")
        ent = carregar(base / "p4_install_entries.json")
        f.add(f"{nome}.fonte", ent["source_entries"], base / "p4_install_entries.json")
        f.add(f"{nome}.unicas", ent["unique_matches_before_flag_lowering"], base / "p4_install_entries.json")
        f.add(f"{nome}.finais", ent["final_install_entries"], base / "p4_install_entries.json")
        f.add(f"{nome}.isr_pct", ent["reduction_percentage"], base / "p4_install_entries.json")
        f.add(f"{nome}.max_por_entrada", ent["maximum_source_rules_per_install_entry"], base / "p4_install_entries.json")
        f.add(f"{nome}.flag_extra", ent["flag_lowering"]["additional_flag_entries"], base / "p4_install_entries.json")
        f.add(f"{nome}.flag_grupos", ent["flag_lowering"]["groups_expanded_by_flags"], base / "p4_install_entries.json")
    f.add("capacidade", carregar(OUT / "backend_validation.json")["table_capacity"], OUT / "backend_validation.json")

    # Particao strong
    for nome, arquivo in (("snort3", AN / "operational_policy_simulation_snort3.json"), ("legacy", AN / "operational_policy_simulation.json")):
        sd = carregar(arquivo)["policies"]["strong_discriminator"]
        rp, ie = sd["rule_partition"], sd["install_entries"]
        f.add(f"{nome}.strong.elegiveis", rp["p4_eligible"], arquivo)
        f.add(f"{nome}.strong.fallback_op", rp["operational_fallback"], arquivo)
        f.add(f"{nome}.strong.fallback_total", rp["operational_fallback"] + rp["unsupported_fallback"], arquivo)
        f.add(f"{nome}.strong.retidas", ie["retained"], arquivo)
        f.add(f"{nome}.strong.removidas", ie["removed"], arquivo)
        f.add(f"{nome}.teto_full_pct", pct(rp["p4_eligible"], 4017), arquivo)

    # Metricas de trace
    tm = carregar(AN / "trace_metrics_by_semantics.json")
    for sem in ("snort3", "legacy"):
        for j, v in tm[sem]["janelas"].items():
            base = f"{sem}.{j}"
            fonte = AN / "trace_metrics_by_semantics.json"
            for k in ("quadros", "elegiveis", "global_candidatos", "strong_candidatos", "strong_no_match"):
                f.add(f"{base}.{k}", v[k], fonte)
            f.add(f"{base}.fora_D", v["quadros"] - v["elegiveis"], fonte)
            f.add(f"{base}.strong_pct", v["strong_candidato_pct"], fonte)
            f.add(f"{base}.strong_nomatch_pct", 100 - v["strong_candidato_pct"], fonte)
            e = v["candidate_set_por_entrada"]
            for k in ("mean", "median", "p90", "p95", "p99", "max"):
                f.add(f"{base}.cs.{k}", e[k], fonte)
            f.add(f"{base}.cs.red", e["reducao"]["sobre_elegiveis_pct"], fonte)
            f.add(f"{base}.cs.red_full", e["reducao"]["sobre_ruleset_pct"], fonte)
            for est, g in v["candidate_set_agrupado"].items():
                f.add(f"{base}.grupo.{est}.mean", g["mean"], fonte)
                f.add(f"{base}.grupo.{est}.median", g["median"], fonte)
                f.add(f"{base}.grupo.{est}.red", g["reducao"]["sobre_elegiveis_pct"], fonte)
                f.add(f"{base}.grupo.{est}.red_full", g["reducao"]["sobre_ruleset_pct"], fonte)
        if sem == "snort3":
            # distancia dos agrupamentos com servico ao nivel de entrada
            janelas = tm[sem]["janelas"].values()
            servico = ("protocol_service", "protocol_direction_service")
            for chave, rotulo in (("sobre_elegiveis_pct", "particao"), ("sobre_ruleset_pct", "ruleset")):
                maior = max(
                    v["candidate_set_por_entrada"]["reducao"][chave] - v["candidate_set_agrupado"][est]["reducao"][chave]
                    for v in janelas for est in servico
                )
                f.add(f"snort3.grupo_servico.distancia_max_{rotulo}", round(maior + 0.005, 2), fonte)
    tq = carregar(AN / "trace_metrics_full_thursday.json")
    for sem in ("snort3", "legacy"):
        v = tq[sem]["janelas"]["quinta_inteira"]
        fonte = AN / "trace_metrics_full_thursday.json"
        f.add(f"{sem}.quinta.quadros", v["quadros"], fonte)
        f.add(f"{sem}.quinta.elegiveis", v["elegiveis"], fonte)
        f.add(f"{sem}.quinta.strong_pct", v["strong_candidato_pct"], fonte)
        f.add(f"{sem}.quinta.cs_mean", v["candidate_set_por_entrada"]["mean"], fonte)
        f.add(f"{sem}.quinta.cs_red", v["candidate_set_por_entrada"]["reducao"]["sobre_elegiveis_pct"], fonte)
        f.add(f"{sem}.quinta.cs_red_full", v["candidate_set_por_entrada"]["reducao"]["sobre_ruleset_pct"], fonte)
        f.add(f"{sem}.quinta.prot_red", v["candidate_set_agrupado"]["protocol"]["reducao"]["sobre_elegiveis_pct"], fonte)

    # Replays no BMv2
    for plano in ("global", "strong"):
        arquivo = AN / "replay_snort3" / plano / "resultado.json"
        for med, d in carregar(arquivo)["medicoes"].items():
            f.add("replay.txqueuelen", int(d["ambiente"]["txqueuelen"]), arquivo)
            assert d["status"] == "ACCOUNTING_VALID", (plano, med)
            f.add(f"replay.{plano}.{med}.enviados", d["enviados"], arquivo)
            for c, n in d["medido"].items():
                f.add(f"replay.{plano}.{med}.{c}", n, arquivo)

    # Entradas amplas e residual
    psa = carregar(AN / "prefilter_selectivity_audit_snort3.json")
    for b in psa["static"]["broad_entries"]:
        f.add(f"amplas.{b['install_entry_id']}.subsume", b["subsumes_install_entries"], AN / "prefilter_selectivity_audit_snort3.json")
        f.add(f"amplas.{b['install_entry_id']}.subsume_pct", b["subsumes_percentage"], AN / "prefilter_selectivity_audit_snort3.json")
        f.add(f"amplas.{b['install_entry_id']}.regras", b["source_rule_count"], AN / "prefilter_selectivity_audit_snort3.json")
    for t in ("sql_injection", "xss"):
        top = psa[t]["top_entries"][0]
        f.add(f"amplas.{t}.{top['install_entry_id']}.pct", top["percentage_of_parser_eligible"], AN / "prefilter_selectivity_audit_snort3.json")
    for nome, arquivo in (("snort3", AN / "residual_selectivity_audit_snort3.json"), ("legacy", AN / "residual_selectivity_audit.json")):
        r = carregar(arquivo)
        for t in ("sql_injection", "xss"):
            f.add(f"residual.{nome}.{t}.top_pct", r[t]["top_entries"][0]["percentage_of_parser_eligible"], arquivo)
            for k, v in r[t]["greedy_cover"].items():
                if k != "selected_entries" and v is not None:
                    f.add(f"residual.{nome}.{t}.{k}", v, arquivo)

    # Agrupamento
    ge = carregar(AN / "grouping_structure_by_semantics.json")
    for sem, d in ge["semanticas"].items():
        for est, b in d["estrategias"].items():
            f.add(f"grupos.{sem}.{est}.n", b["grupos"], AN / "grouping_structure_by_semantics.json")
            f.add(f"grupos.{sem}.{est}.maior", b["maior_grupo"]["regras"], AN / "grouping_structure_by_semantics.json")
            f.add(f"grupos.{sem}.{est}.multi", b["regras_em_mais_de_um_grupo"], AN / "grouping_structure_by_semantics.json")

    # Alertas
    ac = carregar(AN / "alert_coverage_by_semantics.json")
    total = 0
    for j, d in ac["snort3"].items():
        f.add(f"alertas.{j}", d["alertas"], AN / "alert_coverage_by_semantics.json")
        total += d["alertas"]
        for sid, v in d["por_sid"].items():
            f.add(f"alertas.sid.{sid}", int(sid), AN / "alert_coverage_by_semantics.json")
    f.add("alertas.total", total, AN / "alert_coverage_by_semantics.json")
    f.add("alertas.sid254", sum(d["por_sid"].get("254", {}).get("fallback", 0) for d in ac["snort3"].values()), AN / "alert_coverage_by_semantics.json")
    lg = ac["legacy"]["bruteforce"]
    f.add("alertas.legacy.bf.cobertos", lg["cobertos"], AN / "alert_coverage_by_semantics.json")
    f.add("alertas.legacy.bf.fallback", lg["fallback"], AN / "alert_coverage_by_semantics.json")

    # Campanhas
    prov = carregar(CAMP / "e2e_1000_v4" / "proveniencia.json")
    f.add("camp.utilizaveis", prov["regras_utilizaveis"], CAMP / "e2e_1000_v4" / "proveniencia.json")
    f.add("camp.excluidas", 4017 - prov["regras_utilizaveis"], CAMP / "e2e_1000_v4" / "proveniencia.json")
    f.add("camp.nao_sintetizavel", prov["recusas"]["opcao nao sintetizavel"], CAMP / "e2e_1000_v4" / "proveniencia.json")
    f.add("camp.quadros", prov["quadros"], CAMP / "e2e_1000_v4" / "proveniencia.json")
    f.add("camp.casos", prov["casos"], CAMP / "e2e_1000_v4" / "proveniencia.json")
    for campanha in ("e2e_1000_v4", "servico_fora_do_cabecalho"):
        for suf in ("_snort3", "_strong_snort3", "_strong", ""):
            arq = CAMP / campanha / f"relatorio{suf}.json"
            if not arq.exists():
                continue
            rel = carregar(arq)
            for k, v in rel["vereditos"].items():
                f.add(f"camp.{campanha}{suf}.{k}", v, arq)
            for papel in ("testemunha", "negativo_payload", "negativo_header"):
                for c, n in rel[papel].get("categorias", {}).items():
                    f.add(f"camp.{campanha}{suf}.{papel}.{c}", n, arq)
        for suf in ("_snort3", "_strong_snort3", "_strong"):
            arq = CAMP / campanha / f"atribuicao{suf}.json"
            if not arq.exists():
                continue
            at = carregar(arq)
            f.add(f"camp.{campanha}{suf}.so_propria", at["confirmados_so_propria"], arq)
            conc = at["concordancia_predicao_medicao"]
            f.add(f"camp.{campanha}{suf}.concordancia", conc.get("concordam", conc) if isinstance(conc, dict) else conc, arq)
            for ver, cob in at["cobertura_da_testemunha_por_veredito"].items():
                for k, n in cob.items():
                    f.add(f"camp.{campanha}{suf}.{ver}.{k}", n, arq)
    res = jsonl(CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
    fallback = [c for c in res if c["veredito"] == "FALLBACK_OPERACIONAL"]
    flush = [c for c in fallback if "flush" in c["papeis_alertados"]]
    f.add("camp.flush.regras", len(flush), CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
    f.add("camp.flush.nomatch", sum(1 for c in flush if "P4_NO_MATCH" in c["p4_nos_alertados"]), CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
    neg = Counter((c["p4_por_papel"].get("negativo_payload"), "negativo_payload" in c["papeis_alertados"]) for c in res)
    f.add("camp.negpay.cand_sem_alerta", neg[("P4_CANDIDATE", False)], CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
    f.add("camp.negpay.cand_com_alerta", neg[("P4_CANDIDATE", True)], CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
    # negativos de payload separados entre regras pre-filtradas e em fallback
    for lado, casos in (("prefiltradas", [c for c in res if not c["fallback_operacional"]]),
                        ("fallback", [c for c in res if c["fallback_operacional"]])):
        f.add(f"camp.negpay.{lado}.casos", len(casos), CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
        for cat in ("P4_CANDIDATE", "P4_NO_MATCH"):
            f.add(f"camp.negpay.{lado}.{cat}", sum(1 for c in casos if c["p4_por_papel"].get("negativo_payload") == cat),
                  CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
            for alertou in (False, True):
                f.add(f"camp.negpay.{lado}.{cat}.alerta_{alertou}",
                      sum(1 for c in casos if c["p4_por_papel"].get("negativo_payload") == cat
                          and ("negativo_payload" in c["papeis_alertados"]) == alertou),
                      CAMP / "e2e_1000_v4" / "resultado_strong_snort3.jsonl")
    for sid in ("56583", "56584", "43809", "47386", "28982", "309"):
        f.add(f"sid.{sid}", int(sid), "texto (SID citada)")

    # Servico
    exp = carregar(AN / "service_based_header_exposure.json")
    f.add("svc.total", exp["service_based_total"], AN / "service_based_header_exposure.json")
    f.add("svc.service_option", exp["necessarias_com_service_explicito"], AN / "service_based_header_exposure.json")
    for s in ("http", "imap", "pop3", "smtp"):
        f.add(f"svc.{s}", exp["expostas"]["servicos"][s], AN / "service_based_header_exposure.json")
    f.add("svc.user_mode", exp["necessarias_com_protocolo_de_servico_no_cabecalho"]["total"], AN / "service_based_header_exposure.json")
    f.add("svc.porta", exp["expostas"]["elegiveis_no_strong_discriminator"], AN / "service_based_header_exposure.json")
    so_ip = exp["expostas"]["mantendo_so_condicoes_de_ip"]
    f.add("svc.ip_seletivo", so_ip["com_ip_seletivo"] + exp["expostas_por_servico_implicito"]["mantendo_so_condicoes_de_ip"]["com_ip_seletivo"], AN / "service_based_header_exposure.json")
    cob = exp["cobertura_da_regiao_sem_porta_e_protocolo"]["por_plano"]["global"]
    f.add("svc.global_qualquer", cob["qualquer_protocolo"] + 3, AN / "service_based_header_exposure.json")
    f.add("svc.global_so_tcp", cob["so_tcp"], AN / "service_based_header_exposure.json")
    f.add("svc.porta_based", 4003 - exp["service_based_total"] - exp["necessarias_com_protocolo_de_servico_no_cabecalho"]["total"], AN / "service_based_header_exposure.json")
    f.add("svc.full_header", 4003 - exp["service_based_total"], AN / "service_based_header_exposure.json")
    for sid in ("529", "3238", "3239", "1415", "1416", "1941", "28852", "29174", "38993", "56585"):
        f.add(f"sid.{sid}", int(sid), AN / "service_based_header_exposure.json")

    # Flowbits, tetos, regras externas
    fb = carregar(AN / "flowbit_partition_audit.json")["semanticas"]["snort3"]
    f.add("flowbits.semantica", fb["semantica"]["flowbit_edges"]["candidate_to_candidate"], AN / "flowbit_partition_audit.json")
    f.add("flowbits.cruzadas", fb["strong"]["flowbit_edges"]["cross_partition"], AN / "flowbit_partition_audit.json")
    for sid in ("3143", "3144", "3135", "3142", "3145", "3146"):
        f.add(f"sid.{sid}", int(sid), AN / "flowbit_partition_audit.json")
    hb = carregar(AN / "header_precision_bounds_snort3.json")
    for k in ("h12_faixas_de_porta", "m1_itype_icode", "m2_ip_proto"):
        f.add(f"tetos.{k}.regras", hb[k]["fora_do_strong"], AN / "header_precision_bounds_snort3.json")
        f.add(f"tetos.{k}.pontos", hb[k]["teto_pontos_sobre_ruleset"], AN / "header_precision_bounds_snort3.json")
    ex = carregar(AN / "exact_rules_check.json")
    f.add("exatas.regras", ex["regras"], AN / "exact_rules_check.json")
    f.add("exatas.pares", ex["pares_quadro_regra"], AN / "exact_rules_check.json")

    # Valores congelados do legacy que o texto cita como historia
    hist = AN / "ipv4_packet_domain_correction" / "REPLAY_ACCOUNTING_VALIDATION_XSS_BRUTEFORCE.md"
    for nome, v in (("perda_bf", 87), ("perda_bf_pct", 0.008), ("bf_sem_gate", 1101475), ("arp_sqli", 125), ("arp_xss", 1660),
                    ("arp_bf", 4074), ("ipv6_sqli", 195), ("ipv6_xss", 820), ("ipv6_bf", 2523), ("legacy.residual_22", 22)):
        f.add(f"hist.{nome}", v, hist)
    return f


NUMERO = re.compile(r"(?<![\w.,])\d[\d.,]*\d|(?<![\w.,])\d")


def normalizar(token: str, idioma: str) -> str:
    """Leva 4,017 (en) e 4.017 (pt) a 4017; 92.298 (en) e 92,298 (pt) a 92.298."""

    if idioma == "en":
        if re.fullmatch(r"\d{1,3}(,\d{3})+(\.\d+)?", token):
            return token.replace(",", "")
        return token
    if re.fullmatch(r"\d{1,3}(\.\d{3})+(,\d+)?", token) and token.count(".") >= 1 and not re.fullmatch(r"\d+\.\d{1,2}", token):
        return token.replace(".", "").replace(",", ".")
    return token.replace(",", ".")


def limpar_tex(texto: str) -> str:
    texto = re.sub(r"(?m)%.*$", "", texto)
    texto = re.sub(r"\\(ref|label|cite|url|path|includegraphics|setlength|newcolumntype)\{[^}]*\}", " ", texto)
    texto = re.sub(r"L\{\d+\.\d+cm\}", " ", texto)
    texto = re.sub(r"\d+(\.\d+)?(pt|mm|cm|em)\b", " ", texto)
    texto = re.sub(r"p4-\d+", " ", texto)
    texto = re.sub(r"P4\\?_\{?16\}?|P4\$_\{16\}\$", " ", texto)
    return texto


def main() -> int:
    fatos = coletar()
    aceitos = fatos.valores() | ESTRUTURAIS
    resultado = {
        "analise": "manuscript_number_audit",
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gerador": "tests/check_manuscript_numbers.py",
        "fatos": fatos.itens,
        "sem_fato": {},
    }
    problemas = 0
    for nome, (caminho, idioma_do_texto) in MANUSCRITOS.items():
        linhas = caminho.read_text(encoding="utf-8").splitlines()
        orfaos = []
        no_abstract = False
        for n, linha in enumerate(linhas, 1):
            # O abstract das versoes em portugues e em ingles.
            if r"\begin{abstract}" in linha:
                no_abstract = True
            idioma = "en" if no_abstract else idioma_do_texto
            if r"\end{abstract}" in linha:
                no_abstract = False
            texto = limpar_tex(linha)
            for m in NUMERO.finditer(texto):
                token = m.group(0).rstrip(".,")
                valor = normalizar(token, idioma)
                if valor in aceitos:
                    continue
                orfaos.append({"linha": n, "token": token, "normalizado": valor, "contexto": linha.strip()[:110]})
        resultado["sem_fato"][nome] = orfaos
        problemas += len(orfaos)
        print(f"  {nome}: {len(orfaos)} numero(s) sem fato")
        for o in orfaos:
            print(f"    {o['linha']:5d}  {o['token']:>12s}  {o['contexto']}")
    SAIDA.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\n  {len(fatos.itens)} fatos; {SAIDA.relative_to(PROJECT_ROOT)}")
    return 0 if problemas == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
