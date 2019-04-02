/* packet-rpitch.c
 * Routines for Cboe Europe SIS Room Data (RPITCH).
 * Copyright 2010-2019, Dhiren Vekaria <dvekaria@cboe.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <stdio.h>

#include <epan/packet.h>
#include <epan/prefs.h>

int proto_rpitch = -1;
static dissector_handle_t rpitch_handle;

static int hf_rpitch_hdr_message_length     = -1;
static int hf_rpitch_hdr_message_type       = -1;
static int hf_rpitch_hdr_sequence           = -1;
static int hf_rpitch_session_sub_id         = -1;
static int hf_rpitch_username               = -1;
static int hf_rpitch_password               = -1;
static int hf_rpitch_last_received_sequence = -1;
static int hf_rpitch_si                     = -1;
static int hf_rpitch_login_status           = -1;
static int hf_rpitch_timestamp              = -1;
static int hf_rpitch_order_id               = -1;
static int hf_rpitch_side                   = -1;
static int hf_rpitch_quantity               = -1;
static int hf_rpitch_symbol                 = -1;
static int hf_rpitch_price                  = -1;
static int hf_rpitch_room_id                = -1;
static int hf_rpitch_target_id              = -1;
static int hf_rpitch_quote_status           = -1;

static gint ett_rpitch = -1;

#include "packet-rpitch.h"

static void
proto_tree_add_long_price(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    guint64 value = tvb_get_letoh64(tvb, offset);

    proto_tree_add_string_format_value(
            tree, hf, tvb, offset, 8, "",
            "%lu = %lu.%06u", value, value / 1000000, (unsigned) (value % 1000000));
}

static void
proto_tree_add_base36(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    static char BASE36_DIGITS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char buffer[13]; /* order IDs are 12 bytes, add one for the NUL */
    char *op = buffer + 12;
    guint64 value = tvb_get_letoh64(tvb, offset);

    *op-- = '\0';

    do {
        *op-- = BASE36_DIGITS[value % 36];
        value /= 36;
    } while ((value != 0) && (op >= buffer));
    while (op >= buffer) {
        *op-- = '0';
    }

    proto_tree_add_string_format_value(
            tree, hf, tvb, offset, 8, "",
            "%s", buffer);
}

static guint8
dissect_login_request_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != LOGIN_REQUEST_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Login Request");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,      1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1,  1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2,  4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_session_sub_id,         tvb, *offset + 6,  4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_username,               tvb, *offset + 10, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_password,               tvb, *offset + 14, 10, TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_last_received_sequence, tvb, *offset + 24, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_si,                     tvb, *offset + 28, 4,  TRUE);

    *offset += message_size;

    return 1;
}

static guint8
dissect_login_response_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != LOGIN_RESPONSE_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Login Response");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,     1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_login_status,           tvb, *offset + 6, 1,  TRUE);

    *offset += message_size;

    return 1;
}

static guint8
dissect_heartbeat_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != HEARTBEAT_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Heartbeat");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,     1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2, 4,  TRUE);

    *offset += message_size;

    return 1;
}

static guint8
dissect_add_order_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != ADD_ORDER_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Add Order");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,      1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1,  1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2,  4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_timestamp,              tvb, *offset + 6,  8,  TRUE);
    proto_tree_add_base36(msg_tree, hf_rpitch_order_id,             tvb, *offset + 14);
    proto_tree_add_item(msg_tree, hf_rpitch_side,                   tvb, *offset + 22, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_quantity,               tvb, *offset + 23, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_symbol,                 tvb, *offset + 27, 8,  TRUE);
    proto_tree_add_long_price(msg_tree, hf_rpitch_price,            tvb, *offset + 35);
    proto_tree_add_item(msg_tree, hf_rpitch_room_id,                tvb, *offset + 43, 4,  TRUE);

    *offset += message_size;

    return 1;
}

static guint8
dissect_modify_order_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != MODIFY_ORDER_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Modify Order");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,      1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1,  1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2,  4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_timestamp,              tvb, *offset + 6,  8,  TRUE);
    proto_tree_add_base36(msg_tree, hf_rpitch_order_id,             tvb, *offset + 14);
    proto_tree_add_item(msg_tree, hf_rpitch_quantity,               tvb, *offset + 22, 4,  TRUE);
    proto_tree_add_long_price(msg_tree, hf_rpitch_price,            tvb, *offset + 26);

    *offset += message_size;

    return 1;
}

static guint8
dissect_delete_order_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != DELETE_ORDER_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Delete Order");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,      1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1,  1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2,  4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_timestamp,              tvb, *offset + 6,  8,  TRUE);
    proto_tree_add_base36(msg_tree, hf_rpitch_order_id,             tvb, *offset + 14);

    *offset += message_size;

    return 1;
}

static guint8
dissect_symbol_clear_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != SYMBOL_CLEAR_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Symbol Clear");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,      1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1,  1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2,  4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_timestamp,              tvb, *offset + 6,  8,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_symbol,                 tvb, *offset + 14, 8,  TRUE);

    *offset += message_size;

    return 1;
}

static guint8
dissect_room_status_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size = 0;

    if (tvb_length_remaining(tvb, *offset) != ROOM_STATUS_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_rpitch, tvb,
            *offset, message_size, "Room Status");

    msg_tree = proto_item_add_subtree(msg_item, ett_rpitch);

    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_length,     tvb, *offset,      1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_message_type,       tvb, *offset + 1,  1,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_hdr_sequence,           tvb, *offset + 2,  4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_timestamp,              tvb, *offset + 6,  8,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_target_id,              tvb, *offset + 14, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_room_id,                tvb, *offset + 18, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_rpitch_quote_status,           tvb, *offset + 22, 1,  TRUE);

    *offset += message_size;

    return 1;
}

static int
dissect_rpitch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint bytes, offset = 0;
    guint8 hdr_message_type;

    if (!tree) {
        return 0;
    }

    while ((bytes = tvb_length_remaining(tvb, offset))) {
        guint8 result = 0;
        if (bytes < HEARTBEAT_LEN) {
            /* There aren't enough bytes to even decode the header. This must be malformed data. */
            return offset;
        }

        hdr_message_type = tvb_get_guint8(tvb, offset + 1);

        switch (hdr_message_type) {
            case 0xBF: /* Login */
                result = dissect_login_request_message(tvb, tree, &offset);
                break;

            case 0xC0: /* Login Response */
                result = dissect_login_response_message(tvb, tree, &offset);
                break;

            case 0xC1: /* Heartbeat */
                result = dissect_heartbeat_message(tvb, tree, &offset);
                break;

            case 0xC2: /* Add Order */
                result = dissect_add_order_message(tvb, tree, &offset);
                break;

            case 0xC3: /* Modify Order */
                result = dissect_modify_order_message(tvb, tree, &offset);
                break;

            case 0xC4: /* Delete Order */
                result = dissect_delete_order_message(tvb, tree, &offset);
                break;

            case 0xC5: /* Symbol Clear */
                result = dissect_symbol_clear_message(tvb, tree, &offset);
                break;

            case 0xC6:
                result = dissect_room_status_message(tvb, tree, &offset);
                break;
        }

        if (result == 0) {
            return offset;
        }
        else {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "RPITCH");
            col_add_str(pinfo->cinfo, COL_INFO, val_to_str(hdr_message_type, rpitchMessageTypeStrings, "Unknown (%u)"));
        }
    }

    return offset;
}

void
proto_reg_handoff_rpitch(void)
{
    heur_dissector_add("tcp", dissect_rpitch, proto_rpitch);
    rpitch_handle = new_create_dissector_handle(dissect_rpitch, proto_rpitch);
    dissector_add_handle("tcp.port", rpitch_handle);
}

void
proto_register_rpitch(void)
{
    static hf_register_info hf[] = {
            { &hf_rpitch_hdr_message_length,     { "Message Length",                "rpitch.message_length",            FT_UINT8,   BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_hdr_message_type,       { "Message Type",                  "rpitch.message_type",              FT_UINT8,   BASE_HEX,     rpitchMessageTypeStrings, 0x0, NULL, HFILL } },
            { &hf_rpitch_hdr_sequence,           { "Sequence Number",               "rpitch.sequence_number",           FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_session_sub_id,         { "Session Sub ID",                "rpitch.session_sub_id",            FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_username,               { "Username",                      "rpitch.username",                  FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_password,               { "Password",                      "rpitch.password",                  FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_last_received_sequence, { "Last Received Sequence Number", "rpitch.last_received_sequence",    FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_si,                     { "SI",                            "rpitch.si",                        FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_login_status,           { "Login Status",                  "rpitch.login_status",              FT_UINT8,   BASE_DEC,     rpitchLoginResponseStatusStrings, 0x0, NULL, HFILL } },
            { &hf_rpitch_timestamp,              { "Timestamp",                     "rpitch.timestamp",                 FT_UINT64,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_order_id,               { "Order ID",                      "rpitch.order_id",                  FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_side,                   { "Side",                          "rpitch.side",                      FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_quantity,               { "Quantity",                      "rpitch.quantity",                  FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_symbol,                 { "Symbol",                        "rpitch.symbol",                    FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_price,                  { "Price",                         "rpitch.price",                     FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_room_id,                { "Room ID",                       "rpitch.room_id",                   FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_target_id,              { "Target ID",                     "rpitch.target_id",                 FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_rpitch_quote_status,           { "Quote Status",                  "rpitch.quote_status",              FT_UINT8,   BASE_DEC,     rpitchQuoteStatusStrings, 0x0, NULL, HFILL } },
    };
    static gint *ett[] = {
            &ett_rpitch,
    };

    proto_rpitch = proto_register_protocol (
        "Cboe Europe SIS Room Data", /* name */
        "Cboe RPITCH",               /* short name */
        "rpitch"                     /* abbrev */
        );

    proto_register_field_array(proto_rpitch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    prefs_register_protocol(proto_rpitch, NULL);
}
