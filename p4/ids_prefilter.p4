/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>


/* ============================================================
 * Constants
 * ============================================================
 */

const bit<16> TYPE_IPV4 = 0x0800;

const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP  = 6;
const bit<8> PROTO_UDP  = 17;


/* ============================================================
 * Types
 * ============================================================
 */

typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;


/* ============================================================
 * Headers
 * ============================================================
 */

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}


header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}


header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;

    bit<32> seqNo;
    bit<32> ackNo;

    bit<4> dataOffset;
    bit<3> reserved;
    bit<1> ns;

    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;

    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}


/* ============================================================
 * Metadata
 * ============================================================
 */

struct metadata_t {

    /*
     * 1:
     * packet satisfied at least one conservative prefilter
     * predicate.
     *
     * 0:
     * no installed candidate predicate matched.
     *
     * This is NOT equivalent to a Snort detection decision.
     */
    bit<1> prefilter_candidate;

    /*
     * Generic L4 representation shared by TCP and UDP.
     */
    bit<16> l4_src_port;
    bit<16> l4_dst_port;

    /*
     * Conventional 8-bit TCP flag representation:
     *
     * C E U A P R S F
     */
    bit<8> tcp_flags;
}


/* ============================================================
 * Header collection
 * ============================================================
 */

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
    icmp_t     icmp;
}


/* ============================================================
 * Parser
 * ============================================================
 */

parser MyParser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {

    state start {
        transition parse_ethernet;
    }


    state parse_ethernet {

        packet.extract(
            hdr.ethernet
        );

        transition select(
            hdr.ethernet.etherType
        ) {

            TYPE_IPV4:
                parse_ipv4;

            default:
                accept;
        }
    }


    state parse_ipv4 {

        packet.extract(
            hdr.ipv4
        );

        /*
         * The prefilter has a deliberately bounded packet domain:
         * direct Ethernet/IPv4, a base IPv4 header (IHL = 5), and no
         * fragmentation.  The fixed-header parser below cannot safely
         * locate L4 fields when IPv4 options are present, and fragments
         * cannot safely be classified by the L4 predicate table.
         *
         * Packets outside this domain are accepted without L4 extraction.
         * MyIngress marks them as conservative fallback candidates rather
         * than treating them as P4 no-matches.
         */
        transition select(
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset
        ) {

            (4, 5, 0, 0):
                parse_l4;

            /* DF is compatible with an unfragmented packet. */
            (4, 5, 2, 0):
                parse_l4;

            default:
                accept;
        }
    }


    state parse_l4 {

        transition select(
            hdr.ipv4.protocol
        ) {

            PROTO_TCP:
                parse_tcp;

            PROTO_UDP:
                parse_udp;

            PROTO_ICMP:
                parse_icmp;

            default:
                accept;
        }
    }


    state parse_tcp {

        packet.extract(
            hdr.tcp
        );

        transition accept;
    }


    state parse_udp {

        packet.extract(
            hdr.udp
        );

        transition accept;
    }


    state parse_icmp {

        packet.extract(
            hdr.icmp
        );

        transition accept;
    }
}


/* ============================================================
 * Checksum verification
 * ============================================================
 */

control MyVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {

    apply {
    }
}


/* ============================================================
 * Ingress
 * ============================================================
 */

control MyIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {

    /*
     * Counter layout:
     *
     * index 0 = P4 candidate / table hit within the packet domain
     * index 1 = P4 no-match / table miss within the packet domain
     * index 2 = packet-domain fallback (conservative candidate)
     *
     * packets_and_bytes is used because both packet volume
     * and byte volume will later be useful for experimental
     * evaluation.
     */
    counter(
        3,
        CounterType.packets_and_bytes
    ) prefilter_counter;


    /* ========================================================
     * Actions
     * ========================================================
     */

    action send_to_ids() {

        meta.prefilter_candidate = 1;

        prefilter_counter.count(
            0
        );
    }


    action no_prefilter_match() {

        meta.prefilter_candidate = 0;

        prefilter_counter.count(
            1
        );
    }


    action packet_domain_fallback() {

        /*
         * This packet was not safely parsed for selective matching.  It is
         * deliberately delegated as a candidate, never classified as a
         * no-match or a bypass decision.
         */
        meta.prefilter_candidate = 1;

        prefilter_counter.count(
            2
        );
    }


    /* ========================================================
     * IDS prefilter
     * ========================================================
     */

    table ids_prefilter {

        key = {

            hdr.ipv4.protocol:
                ternary;

            hdr.ipv4.srcAddr:
                ternary;

            hdr.ipv4.dstAddr:
                ternary;

            meta.l4_src_port:
                ternary;

            meta.l4_dst_port:
                ternary;

            meta.tcp_flags:
                ternary;
        }


        actions = {

            send_to_ids;

            no_prefilter_match;

            NoAction;
        }


        /*
         * Current final compilation requires 331 install
         * entries.
         *
         * 8192 remains only a prototype BMv2 configuration,
         * not a hardware capacity claim.
         */
        size = 8192;


        default_action = (
            no_prefilter_match()
        );
    }


    /* ========================================================
     * Apply
     * ========================================================
     */

    apply {

        meta.prefilter_candidate = 0;

        meta.l4_src_port = 0;
        meta.l4_dst_port = 0;

        meta.tcp_flags = 0;


        /*
         * Fail open outside the supported packet domain.  This includes
         * non-IPv4 Ethernet frames, IPv4 options, fragments, and parser
         * extraction errors (for example truncated IPv4/TCP headers).
         */
        if (
            standard_metadata.parser_error != error.NoError
            || !hdr.ipv4.isValid()
            || hdr.ipv4.version != 4
            || hdr.ipv4.ihl != 5
            || hdr.ipv4.fragOffset != 0
            || (
                hdr.ipv4.flags != 0
                && hdr.ipv4.flags != 2
            )
        ) {

            packet_domain_fallback();
        } else {

            /* ------------------------------------------------
             * Generic TCP representation
             * ------------------------------------------------
             */
            if (hdr.tcp.isValid()) {

                meta.l4_src_port =
                    hdr.tcp.srcPort;

                meta.l4_dst_port =
                    hdr.tcp.dstPort;

                meta.tcp_flags =
                    hdr.tcp.cwr ++
                    hdr.tcp.ece ++
                    hdr.tcp.urg ++
                    hdr.tcp.ack ++
                    hdr.tcp.psh ++
                    hdr.tcp.rst ++
                    hdr.tcp.syn ++
                    hdr.tcp.fin;
            }


            /* ----------------------------------------------
             * Generic UDP representation
             * ----------------------------------------------
             */
            if (hdr.udp.isValid()) {

                meta.l4_src_port =
                    hdr.udp.srcPort;

                meta.l4_dst_port =
                    hdr.udp.dstPort;
            }


            /* ----------------------------------------------
             * Apply semantic prefilter inside the domain only
             * ----------------------------------------------
             */
            ids_prefilter.apply();
        }


        /*
         * No forwarding or bypass decision is made here.
         *
         * In particular, counter index 1 means only that no
         * compiled candidate predicate matched inside the
         * supported packet domain.
         *
         * It does NOT currently mean that the packet is safe
         * to bypass Snort, because UNSUPPORTED rules remain.
         */
    }
}


/* ============================================================
 * Egress
 * ============================================================
 */

control MyEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {

    apply {
    }
}


/* ============================================================
 * Checksum computation
 * ============================================================
 */

control MyComputeChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {

    apply {

        update_checksum(
            hdr.ipv4.isValid(),

            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },

            hdr.ipv4.hdrChecksum,

            HashAlgorithm.csum16
        );
    }
}


/* ============================================================
 * Deparser
 * ============================================================
 */

control MyDeparser(
    packet_out packet,
    in headers_t hdr
) {

    apply {

        packet.emit(
            hdr.ethernet
        );

        packet.emit(
            hdr.ipv4
        );

        packet.emit(
            hdr.tcp
        );

        packet.emit(
            hdr.udp
        );

        packet.emit(
            hdr.icmp
        );
    }
}


/* ============================================================
 * Switch
 * ============================================================
 */

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
