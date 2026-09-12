"""Vocabulario de campos entre o IR semantico e o backend P4.

Existiam dois vocabularios para o mesmo conjunto de campos, e nada os
reconciliava:

    IR semantico / manifesto     ->  "flags"
    chave da tabela P4           ->  "tcp_flags"

p4_backend.py escrevia a chave do match como "tcp_flags" (add_flags_match)
mas derivava `expansion_fields` das chaves do mapa semantico, onde o campo
se chama "flags". Do outro lado, EXPANDABLE_FIELDS em expand_p4_entries.py
so conhecia "tcp_flags".

A consequencia e um bug latente: um predicado `flags` marcado EXPANDED
produziria `expansion_fields = ["flags"]`, o expansor nao encontraria esse
nome em seu vocabulario e a entrada NUNCA seria expandida — enquanto o match
carregaria um valor de lista em "tcp_flags" que os estagios seguintes nao
sabem normalizar.

Hoje o bug esta adormecido apenas porque assess_flags nunca devolve
EXPANDED, devolvendo PRESERVED ou FALLBACK. Mas docs/semantic_model.md
descreve o modificador `*` de flags exatamente como uma uniao de entradas,
isto e, como EXPANDED — de modo que a documentacao descreve um caminho que
o codigo nao conseguiria executar.

Este modulo passa a ser a fonte unica desse vocabulario.
"""


# Nome do campo no IR semantico -> nome do campo na chave da tabela P4.
#
# Apenas `flags` diverge. Os demais campos tem o mesmo nome dos dois lados e
# estao listados explicitamente para que o mapa seja total: acrescentar um
# campo novo ao backend obriga a decidir seu nome aqui.
SEMANTICO_PARA_BACKEND = {
    "protocol": "protocol",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "flags": "tcp_flags",
}


# Campos do backend que podem carregar alternativas finitas e portanto ser
# materializados em varias entradas pelo estagio de expansao.
EXPANSIVEIS = {
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "tcp_flags",
}


def nome_de_backend(campo_semantico):
    """Traduz o nome do IR para o nome usado na chave da tabela.

    Campo desconhecido volta inalterado: o chamador ja filtrou por
    MATCH_FIELDS antes de chegar aqui, e devolver o proprio nome evita
    mascarar um campo novo com um KeyError distante da causa.
    """

    return SEMANTICO_PARA_BACKEND.get(
        campo_semantico,
        campo_semantico,
    )
