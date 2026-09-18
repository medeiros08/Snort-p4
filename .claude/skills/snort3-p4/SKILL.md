---
name: snort3-p4
description: Consulta a documentacao normativa local de Snort 3, P4_16, BMv2 e P4Runtime antes de afirmar qualquer coisa sobre essas linguagens. Use ao escrever ou revisar compiler/, p4/ e tests/, ao classificar uma opcao de regra, ao mexer em predicado do data plane ou plano P4Runtime, e ao escrever no paper qualquer frase sobre o que a linguagem permite.
---

# Snort 3 e P4: fonte antes de afirmacao

Este projeto afirma coisas sobre duas linguagens que nao controla. O corpus
em `docs/vendor/` existe para que cada afirmacao dessas saia de um arquivo
com commit conhecido, e nao da memoria do modelo.

## A regra

Toda afirmacao sobre semantica de opcao do Snort 3, construcao P4_16,
comportamento do BMv2 ou contrato P4Runtime sai de um `grep` no corpus e e
citada como `caminho:linha`. Isso vale para codigo (comentario que justifica
um tratamento), para classificacao (`SUPPORTED`/`FALLBACK` de um construto)
e para texto do manuscrito.

Quando o `grep` nao acha, a resposta e "o corpus nao cobre isto" mais a
suposicao declarada como suposicao. Inventar a semantica plausivel e o erro
que esta skill existe para impedir: um `FALLBACK` a mais custa seletividade,
um `SUPPORTED` a mais quebra a propriedade conservadora que o projeto
inteiro sustenta.

Corpus ausente (`./scripts/fetch_reference_docs.sh status` diz `ausente`):
baixar com `./scripts/fetch_reference_docs.sh` antes de responder, nao
responder de memoria.

## Mapa do corpus

| Pergunta | Arquivo |
|---|---|
| O que a opcao X de regra faz, quais parametros aceita | `docs/vendor/snort3/doc/reference/snort_reference.text` |
| Buffers, cursor, `fast_pattern`, modificadores de `content` | idem, e `docs/vendor/snort3/doc/user/` |
| Semantica de `byte_test`/`byte_jump`/`byte_extract` | `docs/vendor/snort3/doc/user/byte_*.txt` |
| Conceitos do Snort 3 (fluxo, servico, inspetores) | `docs/vendor/snort3/doc/user/concepts.txt`, `terms.txt` |
| Diferenca de semantica entre Snort 2.x e 3 | `docs/vendor/snort3/doc/upgrade/` |
| Regra da linguagem P4_16 (tipos, parser, tabelas, escopo) | `docs/vendor/p4-spec/p4-16/spec/P4-16-spec.*` |
| Sintaxe exata aceita | `docs/vendor/p4-spec/p4-16/spec/grammar.*` |
| Assinatura de extern, `match_kind`, metadados padrao | `docs/vendor/p4c/p4include/v1model.p4`, `core.p4` |
| Limitacao do compilador / do alvo bmv2 | `docs/vendor/p4c/docs/` |
| Comportamento do alvo: portas, clone, resubmit, contadores | `docs/vendor/bmv2/docs/simple_switch.md` |
| O que o alvo faz de verdade, quando divergir da spec | `docs/vendor/bmv2/targets/simple_switch/simple_switch.cpp`, `primitives.cpp` |
| Formato JSON que o `p4c-bm2-ss` emite | `docs/vendor/bmv2/docs/JSON_format.md` |
| Escrita de entrada, prioridade de ternary, campos de P4Info | `docs/vendor/p4runtime/docs/v1/P4Runtime-Spec.*` |
| Contrato exato do gRPC (mensagens, campos, erros) | `docs/vendor/p4runtime/proto/p4/v1/p4runtime.proto` |

Como o corpus rende no `grep`: no `snort_reference.text` as opcoes aparecem
qualificadas (`content.fast_pattern`, `byte_test.relative`), entao busque
pelo nome da opcao, nao pela frase em prosa. As duas specs estao em Madoko
(`.mdk`) nas versoes fixadas e em AsciiDoc (`.adoc`) nas recentes — por isso
o mapa usa `P4-16-spec.*`; o texto e o mesmo e busca por termo tecnico acha a
secao em qualquer um dos dois.

## O corpus descreve o rig, nao o tip

Cada fonte esta fixada num ref que reproduz o ambiente da metodologia: tag
`3.12.2.0` do Snort, os SHAs exatos dos builds de `p4c` 1.2.4.2 e
`simple_switch_grpc` 1.15.0, e o release de spec anterior a cada um. O branch
default desses projetos esta anos a frente do rig; afirmacao tirada do tip
descreve comportamento que os experimentos nao tinham.

`docs/vendor/MANIFEST.md` registra pin, commit resolvido e por que aquele ref
— cite-o quando a afirmacao for para o manuscrito. Antes de citar, confirme
que o corpus nao derivou:

    ./scripts/fetch_reference_docs.sh status

`DERIVA` em qualquer linha invalida a citacao ate realinhar.

## O que o projeto ja decidiu

Nao rederive o modelo do projeto a partir da spec. As invariantes, as tres
categorias do data plane e a propriedade conservadora estao em `README.md`;
o modelo semantico em `docs/semantic_model.md`; o status por construto em
`docs/snort3_support_matrix.md`; o estado e os resultados congelados em
`CODEX_HANDOFF.md`.

O corpus responde "o que a linguagem permite". Esses quatro respondem "o que
este compilador faz com isso". Divergencia entre os dois e achado a relatar,
nao conflito a resolver silenciosamente — e, se um resultado congelado
estiver envolvido, a correcao vai em documento novo que declara supersessao,
nunca por cima do artefato.
