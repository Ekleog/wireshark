#include "config.h"

#include <epan/packet.h>

#define LORAWAN_PORT 2404

static int proto_lorawan = -1;
static int hf_lorawan_mhdr = -1;
static int hf_lorawan_mic = -1;
static int hf_lorawan_devaddr = -1;
static int hf_lorawan_fctrl = -1;
static int hf_lorawan_fcnt = -1;
static int hf_mhdr_mtype = -1;
static int hf_mhdr_rfu = -1;
static int hf_mhdr_major = -1;
static int hf_fctrl_adr = -1;
static int hf_fctrl_adrackreq = -1;
static int hf_fctrl_ack = -1;
static int hf_fctrl_fpending = -1;
static int hf_fctrl_foptslen = -1;
static int hf_fctrl_fopts = -1;
static int hf_lorawan_fport = -1;
static int hf_lorawan_frmpayload = -1;
static gint ett_lorawan = -1;
static gint ett_mhdr = -1;
static gint ett_fctrl = -1;

#define MTYPE(a, b, c) ((a << 7) | (b << 6) | (c << 5))
static value_string const mhdr_mtype[] = {
    {MTYPE(0, 0, 0), "Join Request"},
    {MTYPE(0, 0, 1), "Join Accept"},
    {MTYPE(0, 1, 0), "Unconfirmed Data Up"},
    {MTYPE(0, 1, 1), "Unconfirmed Data Down"},
    {MTYPE(1, 0, 0), "Confirmed Data Up"},
    {MTYPE(1, 0, 1), "Confirmed Data Down"},
    {MTYPE(1, 1, 0), "Reserved for Future Usage"},
    {MTYPE(1, 1, 1), "Proprietary"},
    {0, NULL}
};
#include <stdio.h>
static guint
dissect_lorawan_macpayload(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 fctrl, fctrl_foptslen;
    proto_item *fctrl_ti;
    proto_tree *fctrl_tree;

    proto_tree_add_item(tree, hf_lorawan_devaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    fctrl = tvb_get_bits8(tvb, 8*offset, 8);
    fctrl_ti = proto_tree_add_item(tree, hf_lorawan_fctrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    fctrl_tree = proto_item_add_subtree(fctrl_ti, ett_fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_adr, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_adrackreq, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_ack, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_fpending, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_foptslen, tvb, offset, 1, fctrl);
    offset += 1;

    proto_tree_add_item(tree, hf_lorawan_fcnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    fctrl_foptslen = fctrl & ((1 << 3) | (1 << 2) | (1 << 1) | (1 << 0));
    /* TODO: Really dissect FOpts */
    printf("fctrl: %08x, foptslen: %d\n", fctrl, fctrl_foptslen);
    proto_tree_add_item(tree, hf_fctrl_fopts, tvb, offset, fctrl_foptslen, ENC_NA);
    offset += fctrl_foptslen;

    proto_tree_add_item(tree, hf_lorawan_fport, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_lorawan_frmpayload, tvb, offset, tvb_reported_length(tvb) - offset - 4, ENC_NA);
    offset += tvb_reported_length(tvb) - offset - 4;

    return offset;
}

static guint
dissect_lorawan_phypayload(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 mhdr;
    proto_item *mhdr_ti;
    proto_tree *mhdr_tree;

    mhdr = tvb_get_bits8(tvb, offset, 8);
    mhdr_ti = proto_tree_add_item(tree, hf_lorawan_mhdr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    mhdr_tree = proto_item_add_subtree(mhdr_ti, ett_mhdr);
    proto_tree_add_item(mhdr_tree, hf_mhdr_mtype, tvb, offset, 1, mhdr);
    proto_tree_add_item(mhdr_tree, hf_mhdr_rfu, tvb, offset, 1, mhdr);
    proto_tree_add_item(mhdr_tree, hf_mhdr_major, tvb, offset, 1, mhdr);
    offset += 1;

    offset = dissect_lorawan_macpayload(tvb, tree, offset);

    proto_tree_add_item(tree, hf_lorawan_mic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_lorawan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* TODO: remove */ pinfo = pinfo; data = data;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaWAN");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *lorawan_tree = NULL;

        ti = proto_tree_add_item(tree, proto_lorawan, tvb, 0, -1, ENC_NA);
        lorawan_tree = proto_item_add_subtree(ti, ett_lorawan);
        dissect_lorawan_phypayload(tvb, lorawan_tree, 0);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_lorawan(void)
{
    static hf_register_info hf[] = {
        { &hf_lorawan_mhdr, {
            "MHDR", "lorawan.mhdr",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL
        }},
        { &hf_lorawan_mic, {
            "MIC", "lorawan.mic",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL
        }},
        { &hf_lorawan_devaddr, {
            "DevAddr", "lorawan.devaddr",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL
        }},
        { &hf_lorawan_fctrl, {
            "FCtrl", "lorawan.fctrl",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL
        }},
        { &hf_lorawan_fcnt, {
            "FCnt", "lorawan.fcnt",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
        }},
        { &hf_mhdr_mtype, {
            "MType", "lorawan.mhdr.mtype",
            FT_UINT8, BASE_HEX,
            VALS(&mhdr_mtype), (1 << 7) | (1 << 6) | (1 << 5),
            NULL, HFILL
        }},
        { &hf_mhdr_rfu, {
            "Reserved", "lorawan.mhdr.rfu",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), (1 << 4) | (1 << 3) | (1 << 2),
            NULL, HFILL
        }},
        { &hf_mhdr_major, {
            "Major", "lorawan.mhdr.major",
            FT_UINT8, BASE_DEC,
            NULL, (1 << 1) | (1 << 0),
            NULL, HFILL
        }},
        { &hf_fctrl_adr, {
            "ADR (Adaptative Data Rate)", "lorawan.fctrl.adr",
            FT_BOOLEAN, 8,
            TFS(&tfs_enabled_disabled), (1 << 7),
            NULL, HFILL
        }},
        { &hf_fctrl_adrackreq, {
            "ADRACKReq", "lorawan.fctrl.adrackreq",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), (1 << 6),
            NULL, HFILL
        }},
        { &hf_fctrl_ack, {
            "ACK", "lorawan.fctrl.ack",
            FT_BOOLEAN, 8,
            TFS(&tfs_ack_nack), (1 << 5),
            NULL, HFILL
        }},
        { &hf_fctrl_fpending, {
            "FPending", "lorawan.fctrl.fpending",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), (1 << 4),
            NULL, HFILL
        }},
        { &hf_fctrl_foptslen, {
            "FOptsLen", "lorawan.fctrl.foptslen",
            FT_UINT8, BASE_DEC,
            NULL, (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0),
            NULL, HFILL,
        }},
        { &hf_fctrl_fopts, {
            "FOpts", "lorawan.fctrl.fopts",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL
        }},
        { &hf_lorawan_fport, {
            "FPort", "lorawan.fport",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL
        }},
        { &hf_lorawan_frmpayload, {
            "FRMPayload", "lorawan.frmpayload",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL
        }}
    };

    static gint *ett[] = {
        &ett_lorawan,
        &ett_mhdr,
        &ett_fctrl
    };

    proto_lorawan = proto_register_protocol(
        "LoRaWAN Protocol",
        "LoRaWAN",
        "lorawan"
    );
    proto_register_field_array(proto_lorawan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lorawan(void)
{
    static dissector_handle_t lorawan_handle;

    lorawan_handle = create_dissector_handle(dissect_lorawan, proto_lorawan);
    dissector_add_uint("104asdu.addr", 32768, lorawan_handle);
    dissector_add_uint("104asdu.addr", 1, lorawan_handle);
    dissector_add_uint("104asdu.addr", 10, lorawan_handle);
}
