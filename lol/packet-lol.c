#include "config.h"
//#include "moduleinfo.h"
#include <epan/packet.h>
#include "packet-lol.h"

#define LoL_PORT 5105
#define LoL_PORT_MIN 5000
#define LoL_PORT_MAX 5500

static int proto_lol = -1;

//byte key[16];
//gboolean isKey = FALSE;

void proto_register_lol(void);
void proto_reg_handoff_lol(void);


static int hf_enet_checksum = -1;
static int hf_enet_peer_id = -1;
static int hf_enet_sent_time = -1;

static int hf_enet_seqnumber = -1;
static int hf_enet_command = -1;
static int hf_enet_channel = -1;

static int hf_enet_proto_header = -1;

static int hf_enet_header = -1;

static int hf_enet_data_length = -1;
static int hf_enet_data = -1;
static int hf_enet_key = -1;

static int hf_enet_ack = -1;
static int hf_enet_ack_seqnum = -1;
static int hf_enet_ack_recvtime = -1;

static int hf_enet_conn = -1;
static int hf_enet_verify_conn = -1;
static int hf_enet_conn_peerid = -1;
static int hf_enet_conn_mtu = -1;
static int hf_enet_conn_window_size = -1;
static int hf_enet_conn_channels = -1;


static int hf_enet_conn_session_id = -1;

static int hf_enet_dc = -1;
static int hf_enet_dc_data = -1;

static int hf_enet_ping = -1;

static int hf_enet_reliable = -1;

static int hf_enet_unreliable = -1;

static int hf_enet_fragment = -1;
static int hf_enet_unsequenced = -1;

static int hf_enet_payload_length = -1;
static int hf_enet_payload = -1;

static int hf_enet_unreliable_seqnum = -1;

static int hf_enet_fragment_startseqnum = -1;
static int hf_enet_fragment_fragcount = -1;
static int hf_enet_fragment_fragnum = -1;
static int hf_enet_fragment_total_length = -1;
static int hf_enet_fragment_offset = -1;

static int hf_enet_throttle = -1;
static int hf_enet_throttle_throttle_interval = -1;
static int hf_enet_throttle_throttle_accel = -1;
static int hf_enet_throttle_throttle_decel = -1;

static int hf_enet_bandwidth_limit = -1;
static int hf_enet_bandwidth_incoming_bandwidth = -1;
static int hf_enet_bandwidth_outgoing_bandwidth = -1;

static int hf_enet_unsequenced_group = -1;



static gint ett_lol = -1;
static gint ett_enet_header = -1;
static gint ett_enet_cmd_header = -1;
static gint ett_enet_ack = -1;
static gint ett_enet_conn = -1;
static gint ett_enet_v_conn = -1;
static gint ett_enet_dc = -1;
static gint ett_enet_ping = -1;
static gint ett_enet_reliable = -1;
static gint ett_enet_unreliable = -1;
static gint ett_enet_fragment = -1;
static gint ett_enet_unsequenced = -1;
static gint ett_enet_limit = -1;
static gint ett_enet_throttle = -1;
static gint ett_enet_lol = -1;





/*
tvbuf->TVB object
pktinfo->Pinfo object
root/tree -> TreeItem object
*/



static void decode_payload (tvbuff_t*, proto_tree*, packet_info*, gint);
static void parse_acknowledge(tvbuff_t*, proto_tree*);

static void parse_connect (tvbuff_t*, proto_tree*);
static void parse_verify_connect(tvbuff_t*, proto_tree*);
static void parse_disconnect(tvbuff_t*, proto_tree*);
static void parse_ping(tvbuff_t*, proto_tree*);

static void parse_reliable(tvbuff_t*, proto_tree*, packet_info*);
static void parse_unreliable(tvbuff_t*, proto_tree*, packet_info*);
static void parse_fragment(tvbuff_t*, proto_tree*);
static void parse_unsequenced(tvbuff_t*, proto_tree*);


static void parse_bandwidth_limit(tvbuff_t*, proto_tree*);
static void parse_packet_throttle(tvbuff_t*, proto_tree*);



//made this because of some weird hex 
static const value_string hcommands[] = {
        { 0, "NONE" },
        { 1, "ACKNOWLEDGE" },
        { 130, "CONNECT" },
        { 131, "VERIFY_CONNECT" },
        { 132, "DISCONNECT" },
        { 133, "PING" },
        { 134, "SEND_RELIABLE" },
        { 135, "SEND_UNRELIABLE" },
        { 136, "SEND_FRAGMENT" },
        { 137, "SEND_UNSEQUENCED" },
        { 138, "BANDWIDTH_LIMIT" },
        { 139, "THROTTLE_CONFIGURE" },
        { 99, "Unknown" },
        { 0, NULL}
};

static const value_string commands[] = {
        { 0, "NONE" },
        { 1, "ACKNOWLEDGE" },
        { 2, "CONNECT" },
        { 3, "VERIFY_CONNECT" },
        { 4, "DISCONNECT" },
        { 5, "PING" },
        { 6, "SEND_RELIABLE" },
        { 7, "SEND_UNRELIABLE" },
        { 8, "SEND_FRAGMENT" },
        { 9, "SEND_UNSEQUENCED" },
        { 10, "BANDWIDTH_LIMIT" },
        { 11, "THROTTLE_CONFIGURE" },
        { 99, "Unknown" },
        { 0, NULL}
};

static const value_string lolcmds[] = {
    { 0x00, "KeyCheck"},
    { 0x0b, "RemoveItem"},
    { 0x11, "S2C_EndSpawn"},
    { 0x14, "C2S_QueryStatusReq"},
    { 0x15, "S2C_SkillUp"},
    { 0x16, "C2S_Ping_Load_Info" },
    { 0x1A, "S2C_AutoAttack"},
    { 0x20, "C2S_SwapItems"},
    { 0x23, "S2C_FogUpdate2"},
    { 0x2A, "S2C_PlayerInfo"},
    { 0x2C, "S2C_ViewAns"},
    { 0x2E, "C2S_ViewReq"},
    { 0x39, "C2S_SkillUp"},
    { 0x3B, "S2C_SpawnProjectile"},
    { 0x3E, "S2C_SwapItems"},
    { 0x3F, "S2C_LevelUp"},
    { 0x40, "S2C_AttentionPing"},
    { 0x42, "S2C_Emotion"},
    { 0x48, "C2S_Emotion"},
    { 0x4C, "S2C_HeroSpawn"},
    { 0x4D, "S2C_Announce"},
    { 0x52, "C2S_StartGame"},
    { 0x54, "S2C_SynchVersion"},
    { 0x56, "C2S_ScoreBord"},
    { 0x57, "C2S_AttentionPing"},
    { 0x5A, "S2C_DestroyProjectile"},
    { 0x5C, "C2S_StartGame"},
    { 0x62, "S2C_StartSpawn"},
    { 0x64, "C2S_ClientReady"},
    { 0x65, "S2C_LoadHero"},
    { 0x66, "S2C_LoadName"},
    { 0x67, "S2C_LoadScreenInfo"},
    { 0x68, "ChatBoxMessage"},
    { 0x6A, "S2C_SetTarget"},
    { 0x6F, "S2C_BuyItemAns"},
    { 0x72, "C2S_MoveReq"},
    { 0x77, "C2S_MoveConfirm"},
    { 0x81, "C2S_LockCamera"},
    { 0x82, "C2S_BuyItemReq"},
    { 0x87, "S2C_SpawnParticle"},
    { 0x88, "S2C_QueryStatusAns"},
    { 0x8F, "C2S_Exit"},
    { 0x92, "SendGameNumber"},
    { 0x95, "S2C_Ping_Load_Info"},
    { 0x9A, "C2S_CastSpell"},
    { 0x9D, "S2C_TurretSpawn"},
    { 0xA4, "C2S_Surrender"},
    { 0xA8, "C2S_StatsConfirm"},
    { 0xAE, "S2C_SetHealth"},
    { 0xAF, "C2S_Click"},
    { 0xB5, "S2C_CastSpellAns"},
    { 0xBA, "S2C_MinionSpawn"},
    { 0xBD, "C2S_SynchVersion"},
    { 0xBE, "C2S_CharLoaded"},
    { 0xC0, "S2C_GameTimer"},
    { 0xC1, "S2C_GameTimerUpdate"},
    { 0xC4, "S2C_CharStats"},
    { 0xD0, "S2C_LevelPropSpawn"},
    { 0xFF, "Batch"}
};

/*

dissect_lol algo:
    proto header
    checksum
    peer id
    sent time

    header
    command
    channel
    seqnumber

    display command2string in column info

    parse based on command

*/
static void dissect_lol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    guint8 cmand = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENET");
    col_clear(pinfo->cinfo, COL_INFO);

    
   
    if (tree) {
        gint offset = 0;
        //guint8 cmand = 0;
         proto_tree *lol_tree = NULL;
        proto_item *ti = NULL;
        proto_item *pheader = NULL;
        proto_tree *proto_header = NULL;
        proto_item *cheader = NULL;
        proto_tree *command_header = NULL;
        

        ti = proto_tree_add_item(tree, proto_lol, tvb, 0, -1, ENC_NA);
        lol_tree = proto_item_add_subtree(ti, ett_lol);

        pheader = proto_tree_add_item(lol_tree, hf_enet_proto_header, tvb, 0, 8, ENC_NA);
        proto_header = proto_item_add_subtree(pheader, ett_enet_header);


        proto_tree_add_item(proto_header, hf_enet_checksum, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(proto_header, hf_enet_peer_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(proto_header, hf_enet_sent_time, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        cheader = proto_tree_add_item(lol_tree, hf_enet_header, tvb, 8, 4, ENC_NA);
        command_header = proto_item_add_subtree(cheader, ett_enet_cmd_header);

        cmand = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(command_header, hf_enet_command, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(command_header, hf_enet_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(command_header, hf_enet_seqnumber, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;


        col_set_str(pinfo->cinfo, COL_INFO, 
            val_to_str(cmand, hcommands, "Unknown (0x%02x)"));


        switch (cmand)
        {
           
            case 129:
                parse_acknowledge(tvb, lol_tree);
                break;
            case 130:
                parse_connect(tvb, lol_tree);
                break;
            case 131:
                parse_verify_connect(tvb, lol_tree);
                break;
            case 132:
                parse_disconnect(tvb, lol_tree);
                break;
            case 133:
                parse_ping(tvb, lol_tree);
                break;
            case 134:
                parse_reliable(tvb, lol_tree, pinfo);
                break;
            case 135:
                parse_unreliable(tvb, lol_tree, pinfo);
                break;
            case 136:
                parse_fragment(tvb, lol_tree);
                break;
            case 137:
                parse_unsequenced(tvb, lol_tree);
                break;
            case 138:
                parse_bandwidth_limit(tvb, lol_tree);
                break;
            case 139:
                parse_packet_throttle(tvb, lol_tree);
                break;
            default:
                break;


        }

    }
    
}


static void parse_acknowledge(tvbuff_t *tvb, proto_tree *tree)
{
        proto_item *ack_buf = NULL;
        proto_tree *ack_tree = NULL;

        ack_buf = proto_tree_add_item(tree, hf_enet_ack, tvb, 0, 4, ENC_NA);
        ack_tree = proto_item_add_subtree(ack_buf, ett_enet_ack);

        proto_tree_add_item(ack_tree, hf_enet_ack_seqnum, tvb, 0, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ack_tree, hf_enet_ack_recvtime, tvb, 2, 2, ENC_BIG_ENDIAN);



}

static void parse_connect(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *conn_buf = NULL;
    proto_tree *conn_tree = NULL;

    conn_buf = proto_tree_add_item(tree, hf_enet_conn, tvb, 0, 36, ENC_NA);
    conn_tree = proto_item_add_subtree(conn_buf, ett_enet_conn);

    proto_tree_add_item(conn_tree, hf_enet_conn_peerid, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_conn_mtu, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_conn_window_size, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_conn_channels, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_bandwidth_incoming_bandwidth, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_bandwidth_outgoing_bandwidth, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_throttle_throttle_interval, tvb, 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_throttle_throttle_accel, tvb, 24, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_throttle_throttle_decel, tvb, 28, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_conn_session_id, tvb, 32, 4, ENC_BIG_ENDIAN);


}

static void parse_verify_connect(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *conn_buf = NULL;
    proto_tree *conn_tree = NULL;

    conn_buf = proto_tree_add_item(tree, hf_enet_verify_conn, tvb, 0, 32, ENC_NA);
    conn_tree = proto_item_add_subtree(conn_buf, ett_enet_v_conn);

    proto_tree_add_item(conn_tree, hf_enet_conn_peerid, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_conn_mtu, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_conn_window_size, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_conn_channels, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_bandwidth_incoming_bandwidth, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_bandwidth_outgoing_bandwidth, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_throttle_throttle_interval, tvb, 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_throttle_throttle_accel, tvb, 24, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conn_tree, hf_enet_throttle_throttle_decel, tvb, 28, 4, ENC_BIG_ENDIAN);

}

static void parse_disconnect(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *dc_buf = NULL;
    proto_tree *dc_tree = NULL;

    dc_buf = proto_tree_add_item(tree, hf_enet_dc, tvb, 0, 4, ENC_NA);
    dc_tree = proto_item_add_subtree(dc_buf, ett_enet_dc);

    proto_tree_add_item(dc_tree, hf_enet_dc_data, tvb, 0, 4, ENC_BIG_ENDIAN);

}

static void parse_ping(tvbuff_t *tvb, proto_tree *tree)
{
    //proto_item *ping_buf = NULL;
    //proto_tree *ping_tree = NULL;
    proto_tree_add_item(tree, hf_enet_ping, tvb, 0, -1, ENC_NA);
    //ping_buf = proto_tree_add_item(tree, hf_enet_ping, tvb, 0, -1, ENC_NA);
    //ping_tree = proto_item_add_subtree(ping_buf, ett_enet_ping);
}

static void parse_reliable(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    proto_item *buf = NULL;
    proto_tree *reliable_tree = NULL;

    buf = proto_tree_add_item(tree, hf_enet_reliable, tvb, 0, -1, ENC_NA);
    reliable_tree = proto_item_add_subtree(buf, ett_enet_reliable);

    proto_tree_add_item (reliable_tree, hf_enet_payload_length, tvb, 0, 2, ENC_BIG_ENDIAN);

    //need to make tvb start at range 2 use another var?
    decode_payload(tvb, reliable_tree, pinfo, 2);

}

static void parse_unreliable(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    proto_item *buf = NULL;
    proto_tree *unreliable_tree = NULL;

    buf = proto_tree_add_item(tree, hf_enet_unreliable, tvb, 0, -1 , ENC_NA);
    unreliable_tree = proto_item_add_subtree(buf, ett_enet_unreliable);

    proto_tree_add_item (unreliable_tree, hf_enet_unreliable_seqnum, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item (unreliable_tree, hf_enet_payload_length, tvb, 2, 2, ENC_BIG_ENDIAN);

    //needs to start at tvb 4 use another var?
    decode_payload(tvb, unreliable_tree, pinfo, 4);
}

static void parse_fragment(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *buf = NULL;
    proto_tree *fragment_tree = NULL;

    buf = proto_tree_add_item(tree, hf_enet_fragment, tvb, 0, -1, ENC_NA);
    fragment_tree = proto_item_add_subtree(buf, ett_enet_fragment);

    proto_tree_add_item (fragment_tree, hf_enet_fragment_startseqnum, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item (fragment_tree, hf_enet_payload_length, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item (fragment_tree, hf_enet_fragment_fragcount, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item (fragment_tree, hf_enet_fragment_fragnum, tvb , 8 , 4 , ENC_BIG_ENDIAN);
    proto_tree_add_item (fragment_tree, hf_enet_fragment_total_length, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item (fragment_tree, hf_enet_payload, tvb, 20, -1, ENC_BIG_ENDIAN);

}

static void parse_unsequenced(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *buf = NULL;
    proto_tree *unsequenced_tree = NULL;

    buf = proto_tree_add_item(tree, hf_enet_unsequenced, tvb, 0, -1, ENC_NA);
    unsequenced_tree = proto_item_add_subtree(buf, ett_enet_unsequenced);

    proto_tree_add_item (unsequenced_tree, hf_enet_unsequenced_group, tvb, 0 , 2 , ENC_BIG_ENDIAN);
    proto_tree_add_item (unsequenced_tree, hf_enet_payload_length, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item (unsequenced_tree, hf_enet_payload,tvb, 4, -1, ENC_BIG_ENDIAN);
}

static void parse_bandwidth_limit(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *buf = NULL;
    proto_tree *limit_tree = NULL;

    buf = proto_tree_add_item(tree, hf_enet_bandwidth_limit, tvb, 0, -1, ENC_NA);
    limit_tree = proto_item_add_subtree(buf, ett_enet_limit);

    proto_tree_add_item(limit_tree, hf_enet_bandwidth_incoming_bandwidth, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(limit_tree, hf_enet_bandwidth_outgoing_bandwidth, tvb, 4, 4, ENC_BIG_ENDIAN);

}

static void parse_packet_throttle (tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *buf = NULL;
    proto_tree *throttle_tree = NULL;

    buf = proto_tree_add_item (tree, hf_enet_throttle, tvb, 0, -1, ENC_NA);
    throttle_tree = proto_item_add_subtree(buf, ett_enet_throttle);

    proto_tree_add_item(throttle_tree, hf_enet_throttle_throttle_interval, tvb, 0 , 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(throttle_tree, hf_enet_throttle_throttle_accel, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(throttle_tree, hf_enet_throttle_throttle_decel, tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void decode_payload (tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint offset)
{
    proto_item *buf = NULL;
    proto_tree *lol_tree = NULL;
    guint8 lolcom = 0;

    buf = proto_tree_add_item (tree, hf_enet_data, tvb, offset, -1, ENC_NA);
    lol_tree = proto_item_add_subtree(buf, ett_enet_lol);

    //check for b64key
    //if no key, then add "No Key found" to tree with b64keyfile
    //exit out

    //if key then add b64key with b64keyfile

    //proto_tree_add_item (lol_tree, hf_enet_data_length, tvb, offset, -1, ENC_BIG_ENDIAN);

    

    proto_tree_add_item (lol_tree, hf_enet_payload, tvb, offset, -1, ENC_BIG_ENDIAN);


            col_append_fstr(pinfo->cinfo, COL_INFO, " Type %s", 
            val_to_str(lolcom, lolcmds, " Unknown (0x%02x)"));

}

void proto_register_lol(void)
{

    /*
    static hf_register_info hf[] = {
        { &hf_PROTOABBREV_FIELDABBREV,
        { “FIELDNAME”,
        “PROTOABBREV.FIELDABBREV”,
        FIELDTYPE, FIELDBASE, FIELDCONVERT, BITMASK, “FIELDDESCR” }
        },
    };
    */
    
    static hf_register_info hf[] = {
        
         { &hf_enet_checksum,
            {"Checksum", "enet.header.checksum",
                    FT_UINT32, BASE_HEX,
                    NULL, 0x0,
                    NULL, HFILL}},

        {   &hf_enet_peer_id,
            {"Peer ID", "enet_proto.peer_id",
                FT_UINT16, BASE_DEC,
                    NULL, 0x0,
                    NULL, HFILL}},

        {   &hf_enet_sent_time,
            {"Sent Time", "enet_proto.sent_time",
                FT_UINT16, BASE_DEC,
                    NULL, 0x0,
                    NULL, HFILL}},
                    
        {   &hf_enet_seqnumber,
            {"Sequence number", "enet_proto.seqnumber",
                FT_UINT16, BASE_DEC,
                    NULL, 0x0,
                    NULL, HFILL}},

        {   &hf_enet_command,
            {"Command", "enet_proto.sent_time",
                FT_UINT8, BASE_DEC, VALS(commands),
                 0x0F,
                NULL, HFILL}},

        {   &hf_enet_channel,
            {"ChannelID", "enet_proto.channel",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},
                
        {   &hf_enet_proto_header,
            {"ENET Protocol Header", "enet_proto.proto_header",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},
                
        {   &hf_enet_header,
            {"ENET Command Header", "enet_proto.header", 
                FT_BYTES,BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},
                
        {   &hf_enet_data_length,
            {"Data length", "enet_proto.data_length",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_data,
            {"LoL Data", "enet_proto.data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_key,
            {"LoL Game Key", "enet_proto.key",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},
        
        {   &hf_enet_ack,
            {"Acknowledge", "enet_proto.acknowledge",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_ack_seqnum,
            {"Sequence Number", "enet_proto.acknowledge.seqnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_ack_recvtime,
            {"Received Time", "enet_proto.acknowledge.recvtime",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},
        
        {   &hf_enet_conn,
            {"Connect", "enet_proto.connect",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_verify_conn,
            {"Verify Connect", "enet_proto.verify_connect",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_conn_peerid,
            {"Outgoing Peer Id", "enet_proto.connect.peerid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_conn_mtu,
            {"MTU", "enet_proto.connect.mtu",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_conn_window_size,
            {"Window Size", "enet_proto.connect.window_size",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_conn_channels,
            {"Channel Count", "enet_proto.connect.channels",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_conn_session_id,
            {"Session Id", "enet_proto.connect.session_id",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_dc,
            {"Disconnect", "enet_proto.disconnect",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}},

        {   &hf_enet_dc_data,
            {"Disconnect Data", "enet_proto.disconnect.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}},

        {   &hf_enet_ping,
            {"Ping", "enet_proto.ping",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}},

        {   &hf_enet_reliable,
            {"Send Reliable", "enet_proto.reliable",
            FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_unreliable,
            {"Send Unreliable", "enet_proto.unreliable",
                FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_fragment,
            {"Send Fragment", "enet_proto.fragment",
                FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_unsequenced,
            {"Send Unsequenced", "enet_proto.unsequenced",
                FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_payload_length,
            {"Payload Length", "enet_proto.payload.length",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_payload,
            {"Payload", "enet_proto.payload",
                FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_unreliable_seqnum,
            {"Unreliable Sequence Number", "enet_proto.unreliable.seqnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_fragment_startseqnum,
            {"Fragment Start Number", "enet_proto.fragment.startseqnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_fragment_fragcount,
            {"Fragment Count", "enet_proto.fragment.count",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_fragment_fragnum,
            {"Fragment Number", "enet_proto.fragment.num",
                FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_fragment_total_length,
            {"Total Length", "enet_proto.fragment.length",
                FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_fragment_offset,
            {"Offset", "enet_proto.fragment.offset",
                FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_unsequenced_group,
            {"Unsequenced Group", "enet_proto.unsequenced.group",
            FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_bandwidth_limit,
            {"Bandwidth Limit", "enet_proto.bandwidth_limit",
            FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_bandwidth_incoming_bandwidth,
            {"Incoming Bandwidth", "enet_proto.bandwidth_limit.incoming_bandwidth",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_bandwidth_outgoing_bandwidth,
            {"Outgoing Bandwidth", "enet_proto.bandwidth_limit.outgoing_bandwidth",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_throttle,
            {"Packet Throttle", "enet_proto.packet_throttle",
            FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_throttle_throttle_interval,
            {"Packet Throttle Interval", "enet_proto.connect.throttle_interval",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL}},

        {   &hf_enet_throttle_throttle_accel,
            {"Packet Throttle Acceleration", "enet_proto.connect.throttle_accel",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        {   &hf_enet_throttle_throttle_decel,
            {"Packet Throttle Deceleration", "enet_proto.connect.throttle_decel",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},
            

    };
    

    /*protocol subtree array */
    static gint *ett[] = {
        &ett_lol,
        &ett_enet_header,
        &ett_enet_cmd_header,
        &ett_enet_ack,
        &ett_enet_conn,
        &ett_enet_v_conn,
        &ett_enet_dc,
        &ett_enet_ping,
        &ett_enet_reliable,
        &ett_enet_unreliable,
        &ett_enet_unsequenced,
        &ett_enet_limit,
        &ett_enet_throttle,
        &ett_enet_fragment,
        &ett_enet_lol
    };
    
    proto_lol = proto_register_protocol (
            "LoL Protocol", /*name*/
            "LoL",          /*short name*/
            "lol"           /*abbrev */
    );
    
    proto_register_field_array(proto_lol, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    

}

void proto_reg_handoff_lol(void)
{
    static dissector_handle_t lol_handle;
    lol_handle = create_dissector_handle(dissect_lol, proto_lol);
    dissector_add_uint("udp.port", LoL_PORT, lol_handle);
}