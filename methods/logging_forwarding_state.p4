#include <core.p4>
#include <v1model.p4>

#define port_t bit<16>
#define VERSION 0xFFFFFFFF

header Ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> typ;
}

header ipv6 {
    bit<4>   version;
    bit<8>   typ;
    bit<20>  fl;
    bit<16>  plen;
    bit<8>   nh;
    bit<8>   hlim;
    bit<128> src;
    bit<128> dst;
}

header ipv6_extension {
    bit<8>  nh;
    bit<8>  hlen;
    bit<48> pad;
    bit<8>  otyp;
    bit<8>  olen;
    bit<8>  track;
    bit<8>  version;
    bit<32> entry;
}

struct user_metadata_t {
    bit<8> version_value;
}

struct digest_umd_s {
    bit<32>  entry;
    bit<8>   version;
    bit<128> dst;
    bit<16>  plen;
    bit<64>  timestamp;
}

header intrinsic_metadata_t {
    bit<64> ingress_global_timestamp;
}

struct headers_t {
    Ethernet_h           ethernet;
    ipv6                 ipv6;
    ipv6_extension       ext;
    intrinsic_metadata_t intrinsic_metadata;
}

/* The parser describes the state machine used to parse packet headers. */
parser parse_headers(packet_in pkt, out headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    /* The state machine always begins parsing with the start state */
    state start {
        /* Fills in the values of the Ethernet header and sets the header as valid. */
        pkt.extract(hdr.ethernet);
        /* Transition to the next state based on the value of the Ethernet type field. */
        transition select(hdr.ethernet.typ) {
            0x86DD:  parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nh) {
            0x00:    parse_ext;
            default: accept;
        }
    }

    state parse_ext {
        pkt.extract(hdr.ext);
        transition accept;
    }
}

control verify_cs(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/*
Control flow prior to egress port selection.
egress_spec can be assigned a value to control which output port a packet will go to.
egress_port should not be accessed.
 */
control ingress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    digest_umd_s digest_umd;
    // register<bit<8>>(1) version;

    /* An action that takes the desired egress port as an argument. */
    action set_egress(port_t port) {
        smd.egress_spec = port;
    }
    /* An action that will cause the packet to be dropped. */
    action drop_packet() {
        mark_to_drop();
    }
    /* Associates user-defined keys with actions */
    table forwarding {
        /* Values that will be used to look up the destination. */
        key = { hdr.ipv6.dst: exact; }
        /* All possible actions that may result from a lookup or table miss. */
        actions = {
            set_egress;
            drop_packet;
        }
        /* The action to take when the table does not find a match for the supplied key. */
        default_action = drop_packet;
    }
    apply {
        /* Apply the forawrding table to all packets. */
        forwarding.apply();
        // version.read(umd.version_value, 0);
        // if (! hdr.ext.isValid()) {
        //     hdr.ext.setValid();
        // }
        // version.read(hdr.ext.version, 0);
        // if (hdr.ext.version != umd.version_value) {
        //     hdr.ext.track = 1;
        // }
        if (smd.egress_spec == 0x0301) {
            digest_umd.entry = hdr.ext.entry;
            // digest_umd.track = hdr.ext.track;
            digest_umd.version = hdr.ext.version;
            digest_umd.dst = hdr.ipv6.dst;
            digest_umd.plen = hdr.ipv6.plen;
            digest_umd.timestamp = hdr.intrinsic_metadata.ingress_global_timestamp;
            digest<digest_umd_s>(1, digest_umd);
        }
    }
}

/*
Control flow after egress port selection.
egress_spec should not be modified. egress_port can be read but not modified. The packet can still be dropped.
*/
control egress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    register<bit<8>>(1) version;
    register<bit<32>>(1) id;

    action no_action() {
        NoAction();
    }

    /*
    Action to add the extension header and update all fields in headers
    that change as a result of the initialization of the extension header.
    */
    action init_extension() {
        hdr.ext.setValid();
        hdr.ext.nh = hdr.ipv6.nh;
        hdr.ext.hlen = 1;
        hdr.ext.otyp = 0x3F;
        hdr.ext.olen = 0x06;
        hdr.ext.track = 0;
        hdr.ipv6.nh = 0x00;
        hdr.ipv6.plen = hdr.ipv6.plen + 16;
        id.read(hdr.ext.entry, 0);
        version.read(hdr.ext.version, 0);
    }

    // /* Action that will cause the packet to be dropped. */
    // action drop_packet() {
    //     mark_to_drop();
    // }

    /*
    Add a version tag if there isn't one yet. If there is already a version tag,
    than this tag is compared with the version tag of this device. If the tags
    are not equal, the packet will be dropped.
    */
    apply {
        version.read(umd.version_value, 0);
        if (! hdr.ext.isValid()) {
            init_extension();
        } else if (hdr.ext.version != umd.version_value) {
            hdr.ext.track = 1;
        }
    }
}

control update_cs(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/* The deparser constructs the outgoing packet by reassembling headers in the order specified. */
control deparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.ext);
    }
}

/* This instantiate the V1 Model Switch */.
V1Switch(parse_headers(), verify_cs(), ingress(), egress(), update_cs(), deparser()) main;
