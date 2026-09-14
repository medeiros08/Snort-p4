# Achados experimentais F-04 e F-05 — analise, causa raiz e alternativas

**Data:** 2026-09-13
**Escopo:** somente analise. Nenhum arquivo do pipeline, nenhum artefato congelado e
nenhuma linha do manuscrito foi alterada na producao deste documento.
**Motivo do documento:** os dois achados tocam resultados ja publicados no
manuscrito. Pela regra de parada do processo de endurecimento, mudancas que
alteram o significado cientifico do trabalho nao sao minhas para decidir.

---

## Correcao de um relato anterior meu

Na fase anterior eu descrevi o F-05 como "a ablacao de agrupamento nao mede
agrupamento" e estimei que corrigi-lo "removeria duas subsecoes do manuscrito".

**Isso estava forte demais e em parte errado.** O manuscrito ja afirma, de forma
explicita e correta, que a reducao nao vem do agrupamento:

> "The 91--96\% reductions in Table~\ref{tab:candidate-rules} were not created
> by grouping. They arise from the mapping of matched P4 entries to their
> source-rule IDs, followed by the union of those provenance sets for each
> packet." — `main.tex:1058`

Essa frase descreve com precisao o que o codigo faz. O autor sabia e registrou.
O achado real e mais estreito do que eu havia dito, e esta enunciado abaixo.

---

## F-05 — a invariancia entre estrategias e uma identidade algebrica, nao uma observacao

### Classificacao: LIMITACAO CONFIRMADA + lacuna de medicao

### Evidencia

Rodando sobre o artefato congelado `output/analysis/grouped_prefilter_feasibility.json`:

| estrategia | grupos | regras/grupo (media) | grupos ativos/pacote | `candidate_rules_per_packet.mean` |
|---|---:|---:|---:|---:|
| `protocol` | 4 | 902,8 | 1,170 | **179,2847898293437** |
| `protocol_direction` | 12 | 301,2 | 1,410 | **179,2847898293437** |
| `protocol_service` | 268 | 23,4 | 1,176 | **179,2847898293437** |
| `protocol_direction_service` | 308 | 20,4 | 1,416 | **179,2847898293437** |

(SQLi; para XSS o valor e 140,48995641964078 nas quatro.)

A granularidade varia 77x — de 4 para 308 grupos — e a metrica nao muda em
nenhuma das 16 casas decimais. `activated_groups_per_packet` **varia**, o que
confirma que `groups` e lido, mas somente para essa outra metrica.

### Causa raiz

`tests/analyze_grouped_prefilter_feasibility.py:142-148`:

```python
for index in matched:
    entry = entries[index]
    rules.update(entry.get("provenance", {}).get("source_rule_ids", []))
    active_groups.add(groups[index])
candidate_sizes.append(len(rules))
```

`rules` e a uniao das `source_rule_ids` das **entradas casadas**. Nao consulta
`groups`. Logo `candidate_rules_per_packet` e invariante por construcao: nenhum
ruleset, nenhuma traca e nenhuma estrategia de agrupamento poderia faze-la
diferir. Observar as quatro iguais nao e evidencia de nada.

O manuscrito apresenta essa invariancia como achado experimental:

> "All four strategies reproduced the same effective per-packet candidate rule
> set, yielding the conclusion \textsc{Grouping Limited by Overlap}."
> — `main.tex:1052`

O que a frase descreve nao poderia ter dado outro resultado.

### O que nao e medido

Num prefiltro agrupado de verdade, um pacote que ativa o grupo `g` manda para o
Snort **todas as regras de `g`** — essa e a definicao de granularidade grossa. A
metrica correta seria:

```
len( uniao de all_group_rules[g] para g em active_groups )
```

O script ja calcula `all_group_rules`, mas so depois do laco e so para
estatisticas de tamanho de grupo. O custo real do agrupamento nunca e medido.

### Quanto isso muda — estimativa a partir do proprio artefato congelado

Na estrategia `protocol` os 4 grupos particionam as 3.611 regras sem
sobreposicao (`rules_in_multiple_groups = 0`, `max_groups_per_rule = 1`) e o
maior grupo tem 3.439 regras. As 20 entradas mais atingidas nas duas tracas
pertencem majoritariamente a `protocol=6`, e as tracas sao HTTP sobre TCP.

| | medido (nivel de entrada) | sob semantica de agrupamento |
|---|---:|---:|
| conjunto candidato por pacote | 179,3 | ~3.439 |
| reducao vs. 3.611 | 95,04% | **~4,8%** |

**A direcao importa:** a conclusao do artigo — agrupamento grosseiro nao ajuda —
nao so continua valendo como fica **muito mais forte**. Hoje o artigo diz que o
agrupamento "nao melhorou" a reducao; a metrica corrigida mostraria que ele a
destruiria, de 95% para menos de 5%. Corrigir isso reforca o argumento.

### Observacao sobre o rotulo da conclusao

`GROUPING_LIMITED_BY_OVERLAP` e uma string fixa no codigo
(`analyze_grouped_prefilter_feasibility.py:268`), nao um valor derivado. O mesmo
vale para `"semantic_coverage_loss": False` (linha 201).

A sobreposicao medida no artefato:

| estrategia | regras em varios grupos | media | max |
|---|---:|---:|---:|
| `protocol` | **0** | 1,000 | 1 |
| `protocol_direction` | 4 | 1,001 | 2 |
| `protocol_service` | 2.358 | 1,739 | 9 |
| `protocol_direction_service` | 2.358 | 1,739 | 9 |

O rotulo descreve bem as duas estrategias de servico e **nao se aplica** as duas
primeiras, onde a sobreposicao e nula ou desprezivel. O texto da discussao ja e
mais cuidadoso que o rotulo: "The observed overlap was particularly relevant to
the service-oriented groupings" (`main.tex:1264`) — o que bate exatamente com a
tabela acima.

### Alternativas

| # | Acao | Custo | Efeito no artigo |
|---|---|---|---|
| A1 | Nada no codigo; uma frase no texto dizendo que a invariancia e por construcao | ~1 h, so texto | Honesto. Nenhum numero muda. Enfraquece a subsecao de ablacao. |
| A2 | Acrescentar `grouped_candidate_rules_per_packet` **ao lado** da metrica atual, sem remover nada | ~2 h de codigo + rig Linux | Metrica nova, tabela nova. Conclusao fica muito mais forte. Nenhum numero existente muda. |
| A3 | Substituir a metrica atual pela agrupada | idem A2 | Invalida a Tabela de ablacao e a subsecao 1049. Nao recomendo: perde a comparacao com o nivel de entrada, que e o resultado principal. |
| A4 | Nao fazer nada | 0 | A frase de `main.tex:1052` segue apresentando uma tautologia como observacao. |

**Minha recomendacao: A2.** E a unica que acrescenta informacao sem descartar
nenhuma. Exige o rig Linux (scapy + os dois pcaps) e nao invalida artefato
congelado algum, porque acrescenta chave nova em vez de reescrever as existentes.

---

## F-04 — a comparacao do split e verdadeira, porem sem poder de discriminacao

### Classificacao: LIMITACAO CONFIRMADA (nao e bug)

**Revisao do meu relato anterior:** eu havia dito que a comparacao era
"vacuamente 0/0". A parte "0/0" esta certa; "vacuamente" precisa de qualificacao,
porque o split **existe de verdade** e o script esta **correto**.

### Evidencia

As tres tracas, do artefato `snort_comparison.json`:

| | bruteforce | sqli | xss |
|---|---:|---:|---:|
| particao de regras (candidato / unsupported) | 4.003 / 14 | 4.003 / 14 | 4.003 / 14 |
| alertas FULL | 2.391 | 150 | 528 |
| alertas do lado candidato | 2.391 | 150 | 528 |
| alertas do lado **unsupported** | **0** | **0** | **0** |
| alertas de SID fora da particao | 0 | 0 | 0 |
| `candidate_missing` / `additional` | 0 / 0 | 0 / 0 | 0 / 0 |
| `unsupported_missing` / `additional` | 0 / 0 | 0 / 0 | 0 / 0 |

E `baseline_full.jsonl` e byte-identico a `candidate.jsonl` nas tres tracas;
`unsupported.jsonl` tem 0 bytes nas tres.

### Causa raiz

O split de 4.017 regras em 4.003 + 14 e real e o script o verifica corretamente,
inclusive checando que nao ha SID nos dois lados e que nenhum alerta veio de
regra fora da particao (`unknown_alerts = 0` — essa checagem passou de verdade).

O que ocorre e que **as 14 regras UNSUPPORTED nao disparam em nenhuma das tres
tracas**. Disso decorre tudo o mais:

- o lado unsupported fica vazio, entao `unsupported_missing/additional` compara
  lista vazia com lista vazia — esse par **nao pode falhar**;
- todo SID que disparou pertence ao lado candidato, entao a particao do baseline
  coincide com o FULL;
- `union_missing/additional` compara `full` com `candidate + []`, ou seja, repete
  a comparacao anterior — nao e uma terceira verificacao independente;
- `candidate_missing = 0` testa que rodar o Snort com 4.003 regras em vez de
  4.017 produz os mesmos alertas. Isso e uma execucao real do Snort, mas remover
  regras que nunca disparam nao poderia mudar a saida.

**Consequencia:** o experimento nao distingue uma particao correta de uma
incorreta. Uma particao que classificasse regras erradamente produziria os mesmos
0/0, desde que as regras mal classificadas fossem silenciosas na traca. O numero
relatado e verdadeiro; o que ele nao tem e poder de teste.

### Relacao com o que o manuscrito ja declara

O manuscrito e cuidadoso com as outras tres medidas de preservacao — declara
explicitamente que a pertinencia de SID "does not validate dynamic stateful Snort
execution" (`main.tex:796`) e que os resultados sao "observed alert preservation,
not formal equivalence" (`main.tex:1082`).

Para a *semantic split preservation* especificamente, essa qualificacao nao
aparece. E a unica das quatro medidas cuja limitacao de poder nao esta declarada.

### Alternativas

| # | Acao | Custo | Efeito no artigo |
|---|---|---|---|
| B1 | Uma frase em Threats to Validity registrando que as 14 regras UNSUPPORTED nao dispararam nas tracas avaliadas e que o 0/0 do lado unsupported e, portanto, nao discriminante | ~30 min, so texto | Nenhum numero muda. Fecha a unica lacuna de declaracao entre as quatro medidas. |
| B2 | B1 + o script passar a **registrar** o poder do teste (ex.: `unsupported_side_exercised: false`) em vez de so reportar 0/0 | ~1 h + rig | Acrescenta chave nova ao artefato. Torna a limitacao visivel no proprio dado. |
| B3 | Escolher uma traca em que alguma das 14 regras dispare | alto; pode nao existir no CICIDS2017 | Daria poder real ao teste. Fora do escopo desta fase. |
| B4 | Nada | 0 | O 0/0 segue lido como confirmacao de uma propriedade que ele nao testa. |

**Minha recomendacao: B1, e B2 se o rig for ligado por outro motivo.** O custo e
uma frase, e ela torna o artigo mais defensavel diante de um revisor que faca
exatamente a conta que eu fiz aqui.

---

## Resumo para decisao

Nenhum dos dois e bug. Nenhum dos dois invalida numero publicado. Ambos sao
questoes de **o que o numero autoriza a concluir**.

- **F-05 / A2** acrescenta uma metrica que fortalece a conclusao do artigo.
  Precisa do rig Linux.
- **F-04 / B1** e uma frase em Threats to Validity. Nao precisa de rig, nao
  precisa de codigo, nao muda nenhum artefato.

B1 e o item de maior retorno por esforco de todo o backlog restante. A2 e o unico
que exige rig e o unico que produz dado novo.

---

## Procedencia

Tudo acima foi obtido por leitura de codigo e consulta aos artefatos congelados
em `output/`, nesta maquina Windows. Nenhum experimento foi reexecutado — os
pcaps do CICIDS2017 e o Snort ficam no rig Linux. A estimativa de ~3.439 regras
sob agrupamento `protocol` e derivada da aritmetica da particao no artefato
(4 grupos, media 902,8, maximo 3.439, soma 3.611, sobreposicao zero) combinada
com o grupo `protocol=6` das entradas mais atingidas; e uma estimativa, nao uma
medicao, e esta rotulada como tal.
