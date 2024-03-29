#include <core.p4>
#include <v1model.p4>

#define port_t bit<16>

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

header extension {
    bit<8>  nh;
    bit<8>  hlen;
    bit<48> pad;
}

header extension_options {
    bit<8>  typ;
    bit<8>  len;
    bit<48> nid;
}

struct user_metadata_t {
    bit<8> cnt;
}

header intrinsic_metadata_t {
    bit<64> ingress_global_timestamp;
}

struct headers_t {
    Ethernet_h      	ethernet;
    ipv6            	ipv6;
    extension  	    	ext;
    extension_options   option;
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
        /* Values that will be used to look up an entry. */
        key = { hdr.ipv6.dst: ternary; }
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
	/* Clones the packet if it leaves the network. */
        if (smd.egress_spec == 0x0301) {
            smd.clone_spec = 0x80000302;
            clone(CloneType.I2E, smd.clone_spec);
        }
    }
}

/*
Control flow after egress port selection.
egress_spec should not be modified. egress_port can be read but not modified. The packet can still be dropped.
*/
control egress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    register<bit<48>>(1) id;

    action no_action() {
        NoAction();
    }

    /*
    Action to add the extension header and set all fields of the header. Also update
    the fields in the IPv6 header that changes as a result of the initialization of
    the extension header..
    */
    action init_exthdr() {
        hdr.ext.setValid();
        hdr.ext.nh = hdr.ipv6.nh;
        hdr.ext.hlen = 0;
        hdr.ipv6.nh = 0x00;
        hdr.ipv6.plen = hdr.ipv6.plen + 8;
    }

    /*
    Action to add an option to the existing extension header. It sets the option as
    as valid and the fields in the option to their correct values. It also updates
    the fields in the IPv6 header.
    */
    action add_option() {
        hdr.option.setValid();
        hdr.ext.hlen = hdr.ext.hlen + 1;
        hdr.option.typ = 0x3F;
        hdr.option.len = 0x06;
        id.read(hdr.new_tag.nid, 0);
        hdr.ipv6.plen = hdr.ipv6.plen + 8;
    }

    /*
    An extension header is initiated when there isn't one yet. An option is added to the extension header. When the packet is a clone a timestamp is set as valid. 
    */
    apply {
        if (! hdr.ext.isValid()) {
            init_exthdr();
        }
        add_option();
        if (smd.instance_type == 0x8) {
            hdr.intrinsic_metadata.setValid();
        }
    }
}

control update_cs(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/* The deparser constructs the outgoing packet by reassembling headers in the order specified. */
control deparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.intrinsic_metadata);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.ext);
        pkt.emit(hdr.option);
    }
}

/* This instantiate the V1 Model Switch */.
V1Switch(parse_headers(), verify_cs(), ingress(), egress(), update_cs(), deparser()) main;
