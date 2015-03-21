/* packet-batsboe.c
 * Routines for BATS Binary Order Entry (BOE).
 * Copyright 2010-2014, Eric Crampton <ecrampton@batstrading.com>
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

int proto_batsboe = -1;
static dissector_handle_t batsboe_handle;

static int hf_batsboe_hdr_start_of_message            = -1;
static int hf_batsboe_hdr_message_length              = -1;
static int hf_batsboe_hdr_message_type                = -1;
static int hf_batsboe_hdr_matching_unit               = -1;
static int hf_batsboe_hdr_sequence_number             = -1;
static int hf_batsboe_session_sub_id                  = -1;
static int hf_batsboe_username                        = -1;
static int hf_batsboe_password                        = -1;
static int hf_batsboe_no_unspecified_unit_replay      = -1;
static int hf_batsboe_number_of_units                 = -1;
static int hf_batsboe_login_response_status           = -1;
static int hf_batsboe_login_response_text             = -1;
static int hf_batsboe_last_received_sequence_number   = -1;
static int hf_batsboe_transaction_time                = -1;
static int hf_batsboe_cl_ord_id                       = -1;
static int hf_batsboe_cancel_reason                   = -1;
static int hf_batsboe_side                            = -1;
static int hf_batsboe_peg_difference                  = -1;
static int hf_batsboe_price                           = -1;
static int hf_batsboe_exec_inst                       = -1;
static int hf_batsboe_ord_type                        = -1;
static int hf_batsboe_time_in_force                   = -1;
static int hf_batsboe_min_qty                         = -1;
static int hf_batsboe_max_remove_pct                  = -1;
static int hf_batsboe_symbol                          = -1;
static int hf_batsboe_symbol_sfx                      = -1;
static int hf_batsboe_currency                        = -1;
static int hf_batsboe_idsource                        = -1;
static int hf_batsboe_security_id                     = -1;
static int hf_batsboe_security_exchange               = -1;
static int hf_batsboe_capacity                        = -1;
static int hf_batsboe_cross_flag                      = -1;
static int hf_batsboe_account                         = -1;
static int hf_batsboe_clearing_firm                   = -1;
static int hf_batsboe_clearing_account                = -1;
static int hf_batsboe_display_indicator               = -1;
static int hf_batsboe_max_floor                       = -1;
static int hf_batsboe_discretion_amount               = -1;
static int hf_batsboe_order_qty                       = -1;
static int hf_batsboe_prevent_match                   = -1;
static int hf_batsboe_maturity_date                   = -1;
static int hf_batsboe_strike_price                    = -1;
static int hf_batsboe_put_or_call                     = -1;
static int hf_batsboe_open_close                      = -1;
static int hf_batsboe_cl_ord_id_batch                 = -1;
static int hf_batsboe_orig_cl_ord_id                  = -1;
static int hf_batsboe_leaves_qty                      = -1;
static int hf_batsboe_last_shares                     = -1;
static int hf_batsboe_last_px                         = -1;
static int hf_batsboe_display_price                   = -1;
static int hf_batsboe_working_price                   = -1;
static int hf_batsboe_base_liquidity_indicator        = -1;
static int hf_batsboe_expire_time                     = -1;
static int hf_batsboe_order_id                        = -1;
static int hf_batsboe_secondary_order_id              = -1;
static int hf_batsboe_routing_inst                    = -1;
static int hf_batsboe_locate_reqd                     = -1;
static int hf_batsboe_cancel_orig_on_reject           = -1;
static int hf_batsboe_order_reject_reason             = -1;
static int hf_batsboe_text                            = -1;
static int hf_batsboe_modify_reject_reason            = -1;
static int hf_batsboe_restatement_reason              = -1;
static int hf_batsboe_exec_id                         = -1;
static int hf_batsboe_sub_liquidity_indicator         = -1;
static int hf_batsboe_access_fee                      = -1;
static int hf_batsboe_contra_broker                   = -1;
static int hf_batsboe_cancel_reject_reason            = -1;
static int hf_batsboe_osi_root                        = -1;
static int hf_batsboe_group_cnt                       = -1;
static int hf_batsboe_ccp                             = -1;
static int hf_batsboe_risk_reset                      = -1;
static int hf_batsboe_cmta_number                     = -1;
static int hf_batsboe_bid_short_price                 = -1;
static int hf_batsboe_bid_order_qty                   = -1;
static int hf_batsboe_bid_discretion_amount           = -1;
static int hf_batsboe_bid_open_close                  = -1;
static int hf_batsboe_ask_short_price                 = -1;
static int hf_batsboe_ask_order_qty                   = -1;
static int hf_batsboe_ask_discretion_amount           = -1;
static int hf_batsboe_ask_open_close                  = -1;
static int hf_batsboe_accepted_count                  = -1;
static int hf_batsboe_rejected_count                  = -1;
static int hf_batsboe_attributed_quote                = -1;
static int hf_batsboe_bulk_order_ids                  = -1;
static int hf_batsboe_bulk_reject_reasons             = -1;
static int hf_batsboe_corrected_size                  = -1;
static int hf_batsboe_party_id                        = -1;
static int hf_batsboe_contra_capacity                 = -1;
static int hf_batsboe_ext_exec_inst                   = -1;
static int hf_batsboe_party_role                      = -1;
static int hf_batsboe_trade_report_type_return        = -1;
static int hf_batsboe_trade_publish_ind_return        = -1;
static int hf_batsboe_large_size                      = -1;
static int hf_batsboe_fee_code                        = -1;
static int hf_batsboe_echo_text                       = -1;
static int hf_batsboe_stop_px                         = -1;
static int hf_batsboe_rout_strategy                   = -1;
static int hf_batsboe_route_delivery_method           = -1;
static int hf_batsboe_ex_destination                  = -1;

static gint ett_batsboe = -1;
static gint ett_batsboe_return_bitfields = -1;

#include "packet-batsboe.h"

/* Converts a byte into a pipe separated list of strings based on a bit_type_definition.
 *
 * For example:
 *
 * 0x41 -> "Symbol | Capacity"
 */
static gchar *
bitfield_to_string(guint8 value, bit_type_definition *bit_defs)
{
    if (value == 0) {
        return g_strdup("<empty>");
    }
    else {
        gchar *array[9];
        gint i = 0, b = 0;

        while (b < 8) {
            if (value & 1) {
                /* This cast is required for a const-correctness issue in glib. */
                array[i++] = (gchar *) bit_defs[b].name;
            }
            ++b;
            value >>= 1;
        }
        array[i++] = NULL;

        return g_strjoinv(" | ", array);
    }
}

/* Writes all 8 bytes which represent return bitfields, expanded out into a human readable format.
 *
 * For example:
 *
 * Order Acknowledgement Bitfields
 *   Bitfield 0: Side | Price | MinQty
 *   Bitfield 1: Symbol | Capacity
 *   ..
 *   ..
 *   Bitfield 7: <empty>
 */
static void
proto_tree_add_return_bitfields(proto_tree *tree, tvbuff_t *tvb, gint start_offset, const gchar *description)
{
    gchar *formatted;
    gint i;
    proto_item *item;
    proto_tree *subtree;

    item = proto_tree_add_text(tree, tvb, start_offset, 8, "%s Bitfields", description);
    subtree = proto_item_add_subtree(item, ett_batsboe);

    for (i = 0; i < 8; ++i) {
        formatted = bitfield_to_string(tvb_get_guint8(tvb, start_offset + i), all_return_bits[i]);
        proto_tree_add_text(subtree, tvb, start_offset + i, 1, "Bitfield %d: %s", i, formatted);
        g_free(formatted);
    }
}

static void
proto_tree_add_submitted_bitfields(proto_tree *tree, tvbuff_t *tvb, gint start_offset, const gchar *description, bit_type_definition **definitions)
{
    gchar *formatted;
    gint i, num_bytes;
    proto_item *item;
    proto_tree *subtree;

    i = num_bytes = 0;
    while (definitions[i++] != NULL) {
        ++num_bytes;
    }

    item = proto_tree_add_text(tree, tvb, start_offset, num_bytes, "%s Bitfields", description);
    subtree = proto_item_add_subtree(item, ett_batsboe);

    i = 0;
    while (definitions[i] != NULL) {
        formatted = bitfield_to_string(tvb_get_guint8(tvb, start_offset + i), definitions[i]);
        proto_tree_add_text(subtree, tvb, start_offset + i, 1, "Bitfield %d: %s", i, formatted);
        g_free(formatted);
        ++i;
    }
}

static gboolean
proto_tree_add_unit_sequences(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint8 num_units, unit;
    guint32 sequence;
    gint remaining;
    proto_item *units_item;
    proto_tree *units_subtree;

    remaining = tvb_length_remaining(tvb, offset);
    if (remaining == 0) {
        return FALSE;
    }

    num_units = tvb_get_guint8(tvb, offset);

    if (remaining < (gint) (1 + ((sizeof(guint8) + sizeof(guint32)) * num_units))) {
        return FALSE;
    }

    units_item = proto_tree_add_item(tree, hf_batsboe_number_of_units, tvb, offset, 1, TRUE);

    ++offset;
    if (num_units) {
        units_subtree = proto_item_add_subtree(units_item, ett_batsboe);
        while (num_units) {
            unit = tvb_get_guint8(tvb, offset);
            sequence = tvb_get_letohl(tvb, offset + 1);

            proto_tree_add_text(units_subtree, tvb, offset, sizeof(guint8) + sizeof(guint32), "Unit: %u, Sequence: %u", unit, sequence);
            offset += sizeof(guint8) + sizeof(guint32);
            --num_units;
        }
    }

    return TRUE;
}

static guint8
dissect_login_request_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint8 num_units;
    guint16 message_size;

    if (tvb_length_remaining(tvb, *offset) < LOGIN_REQUEST_MIN_LEN) {
        return 0;
    }

    /* the number of units determines the ultimate length of the message */
    num_units = tvb_get_guint8(tvb, *offset + 117);
    message_size = 117 + (num_units * 5);

    if (tvb_length_remaining(tvb, *offset) < message_size) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Login Request");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_session_sub_id,             tvb, *offset + 10, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_username,                   tvb, *offset + 14, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_password,                   tvb, *offset + 18, 10, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_no_unspecified_unit_replay, tvb, *offset + 28, 1,  TRUE);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 29,  "Order Acknowledgement");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 37,  "Order Rejected");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 45,  "Order Modified");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 53,  "Order Restated");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 61,  "User Modify Rejected");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 69,  "Order Cancelled");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 77,  "Cancel Rejected");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 85,  "Order Execution");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 93,  "Trade Cancel or Correct");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 101, "Bulk Order Acknowledgement Extended");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 109, "Reserved 1");
    proto_tree_add_unit_sequences(msg_tree, tvb, *offset + 117);

    *offset += message_size;

    return 1;
}

static gboolean
dissect_unit_sequences_param_group(proto_tree *login_tree, tvbuff_t *tvb, gint offset, guint16 param_group_length)
{
    static const int MINIMUM_LENGTH = 5;
    static const int LENGTH_PER_UNIT = 5;

    proto_item *group_item;
    proto_tree *group_tree;
    guint8 number_of_units;
    
    if (tvb_length_remaining(tvb, offset) < MINIMUM_LENGTH) {
        return FALSE; /* smaller than minimum size */
    }

    number_of_units = tvb_get_guint8(tvb, offset + 4);
    
    group_item = proto_tree_add_protocol_format(
            login_tree, proto_batsboe, tvb,
            offset, param_group_length, "Unit Sequences Parameter Group (0x%x)", 0x80);

    group_tree = proto_item_add_subtree(group_item, ett_batsboe);
    proto_tree_add_item(group_tree, hf_batsboe_no_unspecified_unit_replay, tvb, offset + 3, 1, TRUE);

    if (tvb_length_remaining(tvb, offset + 5) < number_of_units * LENGTH_PER_UNIT) {
        return FALSE; /* not enough data for number of units expected */
    }

    if (param_group_length != (MINIMUM_LENGTH + number_of_units * LENGTH_PER_UNIT)) {
        return FALSE; /* parameter group length not correct for number of units expected */
    }

    proto_tree_add_unit_sequences(group_tree, tvb, offset + 4);

    return TRUE;
}

static void
dissect_return_bitfields_param_group(proto_tree *msg_tree, tvbuff_t *tvb, gint offset)
{

}

static guint8
dissect_login_request_v2_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;
    guint8 num_param_groups;
    guint8 current_param_group;
    gint current_offset;
    
    if (tvb_length_remaining(tvb, *offset) < LOGIN_REQUEST_V2_MIN_LEN) {
        return 0;
    }

    message_size = tvb_get_guint8(tvb, *offset + 2);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Login Request V2");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_session_sub_id, tvb, *offset + 10, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_username,       tvb, *offset + 14, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_password,       tvb, *offset + 18, 10, TRUE);
    
    num_param_groups = tvb_get_guint8(tvb, *offset + 28);
    printf("#of param groups: %u\n", num_param_groups);
    
    current_offset = *offset + 29;
    
    for (current_param_group = 0; current_param_group < num_param_groups; ++current_param_group) {
        guint16 param_group_length;
        guint8 param_group_type;

        if (tvb_length_remaining(tvb, current_offset) < 3) {
            return 0;
        }
        param_group_length = tvb_get_letohs(tvb, current_offset);
        
        if (tvb_length_remaining(tvb, current_offset) < param_group_length) {
            /* insufficient bytes remaining */
            printf("short [%u]: %u < %u\n", current_param_group, tvb_length_remaining(tvb, current_offset), param_group_length);
            return 0;
        }

        param_group_type = tvb_get_guint8(tvb, current_offset + 2);
        switch (param_group_type) {
            case 0x80:
                printf("dissect uspg\n");
                /* TODO: retval */ dissect_unit_sequences_param_group(msg_tree, tvb, current_offset, param_group_length);
                break;

            case 0x81:
                printf("dissect rbpg\n");
                /* TODO: retval */ dissect_return_bitfields_param_group(msg_tree, tvb, current_offset);
                break;

            default:
                break;
        }

        printf("%u + %u = %u\n", current_offset, param_group_length, current_offset + param_group_length);
        current_offset += param_group_length;
    }

    /* if (current_offset != message_size) { */
    /*     printf("size problem: %u != %u\n", current_offset, message_size); */
    /* } */

    *offset += message_size;
    
    return 1;
}

static guint8
dissect_login_response_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint8 num_units, unit_counter;
    guint16 message_size;
    proto_item *units;
    proto_tree *units_subtree;
    gint unit_offset;

    if (tvb_length_remaining(tvb, *offset) < LOGIN_RESPONSE_MIN_LEN) {
        return 0;
    }

    /* the number of units determines the ultimate length of the message */
    num_units = tvb_get_guint8(tvb, *offset + 164);
    message_size = 164 + (num_units * 5);

    if (tvb_length_remaining(tvb, *offset) < message_size) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Login Response");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_login_response_status,      tvb, *offset + 10, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_login_response_text,        tvb, *offset + 11, 60, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_no_unspecified_unit_replay, tvb, *offset + 71, 1,  TRUE);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 72,  "Order Acknowledgement");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 80,  "Order Rejected");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 88,  "Order Modified");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 96,  "Order Restated");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 104, "User Modify Rejected");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 112, "Order Cancelled");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 120, "Cancel Rejected");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 128, "Order Execution");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 136, "Trade Cancel or Correct");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 144, "Bulk Order Acknowledgement Extended");
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 152, "Reserved 1");

    proto_tree_add_item(msg_tree, hf_batsboe_last_received_sequence_number, tvb, *offset + 160, 4, TRUE);
    units = proto_tree_add_item(msg_tree, hf_batsboe_number_of_units, tvb, *offset + 164, 1, TRUE);
    units_subtree = proto_item_add_subtree(units, ett_batsboe);

    for (unit_counter = 0, unit_offset = *offset + 165; unit_counter < num_units; ++unit_counter, unit_offset += sizeof(guint8) + sizeof(guint32)) {
        guint8 unit;
        guint32 sequence;

        unit = tvb_get_guint8(tvb, unit_offset);
        sequence = tvb_get_letohl(tvb, unit_offset + 1);

        proto_tree_add_text(units_subtree, tvb, unit_offset, sizeof(unit) + sizeof(sequence), "Unit: %u, Sequence: %u", unit, sequence);
    }

    *offset += message_size;

    return 1;
}

static void
proto_tree_add_long_price(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    guint64 value = tvb_get_letoh64(tvb, offset);

    proto_tree_add_string_format_value(
            tree, hf, tvb, offset, 8, "",
            "%lu = %lu.%04u", value, value / 10000, (unsigned) (value % 10000));
}

static void
proto_tree_add_short_price(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    guint32 value = tvb_get_letohl(tvb, offset);

    proto_tree_add_string_format_value(
            tree, hf, tvb, offset, 4, "",
            "%u = %u.%04u", value, value / 10000, (unsigned) (value % 10000));
}

static void
proto_tree_add_base36(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    static char BASE36_DIGITS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char buffer[13]; /* order IDs are 12 bytes, execution IDs are 9 bytes, add one for the NUL */
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

static gint
proto_tree_add_bitfield_values(proto_tree *tree, tvbuff_t *tvb, gint offset, bit_type_definition **definitions, gint extra_offset)
{
    gint return_bitfields, i, bit_i, return_byte;
    bit_type_definition *definition;
    gint original_offset = offset;

    return_bitfields = offset;
    i = 0;
    while (definitions[i++] != NULL) {
        ++offset;
    }

    offset += extra_offset;

    i = 0;
    while (definitions[i] != NULL) {
        return_byte = tvb_get_guint8(tvb, return_bitfields + i);
        definition = definitions[i];
        for (bit_i = 0; bit_i < 8; ++bit_i) {
            bit_type_definition *bit_type = &(definition[bit_i]);
            if (return_byte & (1 << bit_i)) {
                if (bit_type->hfindex == NULL) return FALSE;

                if (tvb_length_remaining(tvb, offset) < bit_type->length) return FALSE;

                switch (bit_type->type) {
                    case bft_long_price:
                        proto_tree_add_long_price(tree, *(bit_type->hfindex), tvb, offset);
                        break;

                    case bft_short_price:
                        proto_tree_add_short_price(tree, *(bit_type->hfindex), tvb, offset);
                        break;

                    case bft_base36:
                        proto_tree_add_base36(tree, *(bit_type->hfindex), tvb, offset);
                        break;

                    case bft_default:
                        proto_tree_add_item(tree, *bit_type->hfindex, tvb, offset, bit_type->length, TRUE);
                        break;
                }

                offset += bit_type->length;
            }
        }
        ++i;
    }

    return offset - original_offset;
}

static gboolean
proto_tree_add_bulk_orders(proto_tree *tree, tvbuff_t *tvb, gint group_cnt, gint offset, gint bulk_order_bits_offset, const char *str)
{
    gint group_size = 6; /* symbol */
    gint i, bit, group;
    guint8 msg_bulk_order_bits[2];

    msg_bulk_order_bits[0] = tvb_get_guint8(tvb, bulk_order_bits_offset);
    msg_bulk_order_bits[1] = tvb_get_guint8(tvb, bulk_order_bits_offset + 1);

    for (i = 0; i < 2; ++i) {
        for (bit = 0; bit < 8; ++bit) {
            if (msg_bulk_order_bits[i] & (1 << bit)) {
                group_size += bulk_order_group_bits[i][bit].length;
            }
        }
    }

    for (group = 0; group < group_cnt; ++group) {
        proto_tree *group_item;
        proto_tree *group_tree;

        if (tvb_length_remaining(tvb, offset) < group_size) {
            return FALSE;
        }

        group_item = proto_tree_add_protocol_format(tree, proto_batsboe, tvb, offset, group_size, "%s", str);
        group_tree = proto_item_add_subtree(group_item, ett_batsboe);

        proto_tree_add_item(group_tree, hf_batsboe_symbol, tvb, offset, 6, TRUE);
        offset += 6;

        for (i = 0; i < 2; ++i) {
            for (bit = 0; bit < 8; ++bit) {
                if (msg_bulk_order_bits[i] & (1 << bit)) {
                    if (tvb_length_remaining(tvb, offset) < bulk_order_group_bits[i][bit].length) return FALSE;

                    switch (bulk_order_group_bits[i][bit].type) {
                        case bft_short_price:
                            proto_tree_add_short_price(group_tree, *(bulk_order_group_bits[i][bit].hfindex), tvb, offset);
                            break;

                        case bft_long_price:
                            proto_tree_add_long_price(group_tree, *(bulk_order_group_bits[i][bit].hfindex), tvb, offset);
                            break;

                        case bft_base36:
                            proto_tree_add_base36(group_tree, *(bulk_order_group_bits[i][bit].hfindex), tvb, offset);
                            break;

                        case bft_default:
                            proto_tree_add_item(group_tree, *(bulk_order_group_bits[i][bit].hfindex), tvb, offset, bulk_order_group_bits[i][bit].length, TRUE);
                            break;
                    }

                    offset += bulk_order_group_bits[i][bit].length;
}
            }
        }
    }

    return TRUE;
}

static gboolean
proto_tree_add_bulk_ack_ext_groups(proto_tree *tree, tvbuff_t *tvb, gint group_cnt, gint offset, gint bulk_ack_ext_bits_offset)
{
    gint group_size = 0;
    gint i, group;
    guint8 bulk_ack_ext_bits = tvb_get_guint8(tvb, bulk_ack_ext_bits_offset + 5);

    /* BulkOrderIDs bit check */
    if (bulk_ack_ext_bits & (1 << 5)) {
        group_size += all_return_bits[5][5].length * 2;
    }

    /* BulkRejectReasons bit check */
    if (bulk_ack_ext_bits & (1 << 6)) {
        group_size += all_return_bits[5][6].length * 2;
    }

    for (group = 0; group < group_cnt; ++group) {
        proto_tree *group_item;
        proto_tree *group_tree;

        if (tvb_length_remaining(tvb, offset) < group_size) {
            return FALSE;
        }

        group_item = proto_tree_add_protocol_format(tree, proto_batsboe, tvb, offset, group_size, "Bulk Order Group");
        group_tree = proto_item_add_subtree(group_item, ett_batsboe);

        for (i = 0; i < 2; ++i) {
            /* BulkOrderIDs */
            if (bulk_ack_ext_bits & (1 << 5)) {
                if (tvb_length_remaining(tvb, offset) < all_return_bits[5][5].length) {
                    return FALSE;
                }

                proto_tree_add_base36(group_tree, *(all_return_bits[5][5].hfindex), tvb, offset);
                offset += all_return_bits[5][5].length;
            }

            /* BulkRejectReasons */
            if (bulk_ack_ext_bits & (1 << 6)) {
                if (tvb_length_remaining(tvb, offset) < all_return_bits[5][6].length) {
                    return FALSE;
                }

                proto_tree_add_item(group_tree, *(all_return_bits[5][6].hfindex),
                        tvb, offset, all_return_bits[5][6].length, TRUE);
                offset += all_return_bits[5][6].length;
            }
        }
    }

    return TRUE;
}

static guint8
dissect_order_cancelled_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Order Cancelled");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_transaction_time,      tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 18, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cancel_reason,         tvb, *offset + 38, 1,  TRUE);
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 39, "Order Cancelled");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 39, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_cancel_rejected_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Cancel Rejected");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_transaction_time,      tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 18, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cancel_reject_reason,  tvb, *offset + 38, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_text,                  tvb, *offset + 39, 60, TRUE);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 99, "Cancel Rejected");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 99, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_order_execution_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Order Execution");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_transaction_time,         tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id,                tvb, *offset + 18, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_exec_id,                  tvb, *offset + 38, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_last_shares,              tvb, *offset + 46, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_last_px,                  tvb, *offset + 50, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_leaves_qty,               tvb, *offset + 58, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_base_liquidity_indicator, tvb, *offset + 62, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_sub_liquidity_indicator,  tvb, *offset + 63, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_access_fee,               tvb, *offset + 64, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_contra_broker,            tvb, *offset + 72, 4,  TRUE);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 76, "Order Execution");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 76, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_user_modify_rejected_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "User Modify Rejected");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_transaction_time,      tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 18, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_modify_reject_reason,  tvb, *offset + 38, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_text,                  tvb, *offset + 39, 60,  TRUE);
    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 99, "User Modify Rejected");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 99, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_order_acknowledgement_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Order Acknowledgement");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item  (msg_tree, hf_batsboe_transaction_time,      tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item  (msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 18, 20, TRUE);
    proto_tree_add_base36(msg_tree, hf_batsboe_order_id,              tvb, *offset + 38);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 46, "Order Acknowledgement");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 46, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_order_rejected_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Order Rejected");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_transaction_time,      tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 18, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_order_reject_reason,   tvb, *offset + 38, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_text,                  tvb, *offset + 39, 60, TRUE);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 99, "Order Rejected");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 99, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_order_modified_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Order Modified");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item  (msg_tree, hf_batsboe_transaction_time,      tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item  (msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 18, 20, TRUE);
    proto_tree_add_base36(msg_tree, hf_batsboe_order_id,              tvb, *offset + 38);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 46, "Order Modified");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 46, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_order_restated_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Order Restated");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item  (msg_tree, hf_batsboe_transaction_time,      tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item  (msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 18, 20, TRUE);
    proto_tree_add_base36(msg_tree, hf_batsboe_order_id,              tvb, *offset + 38);
    proto_tree_add_item  (msg_tree, hf_batsboe_restatement_reason,    tvb, *offset + 46, 1,  TRUE);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 47, "Order Restated");
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 47, all_return_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_modify_order_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Modify Order");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 10, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_orig_cl_ord_id,        tvb, *offset + 30, 20, TRUE);
    proto_tree_add_submitted_bitfields(msg_tree, tvb, *offset + 50, "Modify Order", modify_order_bits);
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 50, modify_order_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_new_order_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "New Order");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id,             tvb, *offset + 10, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_side,                  tvb, *offset + 30, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_order_qty,             tvb, *offset + 31, 4,  TRUE);
    proto_tree_add_submitted_bitfields(msg_tree, tvb, *offset + 35, "New Order", new_order_bits);
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 35, new_order_bits, 0);

    *offset += message_size;

    return 1;
}

static guint8
dissect_bulk_order(tvbuff_t *tvb, proto_tree *tree, gint *offset, guint8 message_type)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;
    guint16 group_cnt;
    gint v;

    /* Dynamically determine which Bulk Order type and group text
     * to display
     */
    const char *order_str = val_to_str(message_type, boeMessageTypeStrings, "Unknown (%u)");
    gchar *order_group_str = g_strdup_printf("%s Group", order_str);

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        g_free(order_group_str);
        return 0;
    }

    group_cnt = tvb_get_letohs(tvb, 40);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "%s", order_str);

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id_batch, tvb, *offset + 10, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_osi_root,        tvb, *offset + 30, 6,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_order_qty,       tvb, *offset + 36, 4,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_group_cnt,       tvb, *offset + 40, 2,  TRUE);
    proto_tree_add_submitted_bitfields(msg_tree, tvb, *offset + 42, order_str, bulk_order_bits);
    proto_tree_add_submitted_bitfields(msg_tree, tvb, *offset + 48, order_group_str, bulk_order_group_bits);
    v = proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 42, bulk_order_bits, 2);
    proto_tree_add_bulk_orders(msg_tree, tvb, group_cnt, *offset + 42 + v, 48, order_group_str);

    *offset += message_size;

    g_free(order_group_str);

    return 1;
}

static guint8
dissect_bulk_order_ack(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;
    guint16 num_orders;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    num_orders = tvb_get_letohs(tvb, 40);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Bulk Order Acknowledgement (%u order(s))", num_orders);

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_transaction_time,    tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id_batch,     tvb, *offset + 18, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_accepted_count,      tvb, *offset + 38, 2,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_rejected_count,      tvb, *offset + 40, 2,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_order_reject_reason, tvb, *offset + 42, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_text,                tvb, *offset + 43, 60, TRUE);

    *offset += message_size;

    return 1;
}

static guint8
dissect_bulk_order_ack_ext(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;
    guint16 group_cnt;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    group_cnt = tvb_get_letohs(tvb, 38);

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Bulk Order Acknowledgement Extended");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_transaction_time,    tvb, *offset + 10, 8,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_cl_ord_id_batch,     tvb, *offset + 18, 20, TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_group_cnt,           tvb, *offset + 38, 2,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_accepted_count,      tvb, *offset + 40, 2,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_rejected_count,      tvb, *offset + 42, 2,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_order_reject_reason, tvb, *offset + 44, 1,  TRUE);
    proto_tree_add_item(msg_tree, hf_batsboe_text,                tvb, *offset + 45, 60, TRUE);

    proto_tree_add_return_bitfields(msg_tree, tvb, *offset + 105, "Bulk Order Acknowledgement Extended");

    proto_tree_add_bulk_ack_ext_groups(msg_tree, tvb, group_cnt, *offset + 113, 105);

    *offset += message_size;

    return 1;
}

static guint8
dissect_cancel_order_message(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    guint16 message_size;

    message_size = tvb_get_letohs(tvb, 2);

    if (tvb_length_remaining(tvb, *offset) < message_size - 2) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_batsboe, tvb,
            *offset, message_size, "Cancel Order");

    msg_tree = proto_item_add_subtree(msg_item, ett_batsboe);

    proto_tree_add_item(msg_tree, hf_batsboe_orig_cl_ord_id,        tvb, *offset + 10, 20, TRUE);
    proto_tree_add_submitted_bitfields(msg_tree, tvb, *offset + 30, "Cancel Order", cancel_order_bits);
    proto_tree_add_bitfield_values(msg_tree, tvb, *offset + 30, cancel_order_bits, 0);

    *offset += message_size;

    return 1;
}

static int
dissect_batsboe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static const char START_OF_MESSAGE[] = { 0xBA, 0xBA };
    gint bytes, offset = 0;
    proto_item *item;
    proto_tree *batsboe_tree;
    guint16 hdr_start_of_message;
    guint16 hdr_length;
    guint8 hdr_message_type;
    guint8 result = 0;

    if (!tree) {
        return 0;
    }

    while ((bytes = tvb_length_remaining(tvb, offset))) {
        if (bytes < MESSAGE_HEADER_LEN) {
            /* There aren't enough bytes to even decode the header. This must be malformed data. */
            return offset;
        }

        if (tvb_memeql(tvb, 0, START_OF_MESSAGE, 2)) {
            return offset;
        }

        hdr_start_of_message = tvb_get_letohs(tvb, offset);
        (void) hdr_start_of_message; /* TODO */
        hdr_length = tvb_get_letohs(tvb, offset + 2);
        hdr_message_type = tvb_get_guint8(tvb, offset + 4);

        if ((bytes - 2) < hdr_length) {
            /* The number of bytes in the datagram doesn't match what the header says it should be. This
               must be malformed data. */
            return offset;
        }

        if (hdr_message_type == 0x03 || hdr_message_type == 0x09) {
            const char *direction = hdr_message_type == 0x03 ? "Client" : "Server";

            /* client heartbeat */
            item = proto_tree_add_protocol_format(
                    tree, proto_batsboe, tvb,
                    offset,
                    offset + 10, "BATS BOE Header (%s Heartbeat)",
                    direction);
        }
        else {
            item = proto_tree_add_protocol_format(
                    tree, proto_batsboe, tvb,
                    offset,
                    offset + hdr_length + 2, "BATS BOE Message Header");
        }

        batsboe_tree = proto_item_add_subtree(item, ett_batsboe);

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "BOE");
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(hdr_message_type, boeMessageTypeStrings, "Unknown (%u)"));

        /* header */
        proto_tree_add_item(batsboe_tree, hf_batsboe_hdr_start_of_message, tvb, offset, 2, TRUE);
        proto_tree_add_item(batsboe_tree, hf_batsboe_hdr_message_length,   tvb, offset + 2, 2, TRUE);
        proto_tree_add_item(batsboe_tree, hf_batsboe_hdr_message_type,     tvb, offset + 4, 1, TRUE);
        proto_tree_add_item(batsboe_tree, hf_batsboe_hdr_matching_unit,    tvb, offset + 5, 1, TRUE);
        proto_tree_add_item(batsboe_tree, hf_batsboe_hdr_sequence_number,  tvb, offset + 6, 4, TRUE);

        switch (hdr_message_type) {
            case 0x01:
                result = dissect_login_request_message(tvb, batsboe_tree, &offset);
                break;

            case 0x02: /* logout request */
                /* do nothing else */
                break;

            case 0x03: /* client heartbeat */
                /* do nothing else */
                break;

            case 0x04:
                result = dissect_new_order_message(tvb, batsboe_tree, &offset);
                break;

            case 0x05: /* cancel order */
                result = dissect_cancel_order_message(tvb, batsboe_tree, &offset);
                break;

            case 0x06: /* modify order */
                result = dissect_modify_order_message(tvb, batsboe_tree, &offset);
                break;

            case 0x07:
                result = dissect_login_response_message(tvb, batsboe_tree, &offset);
                break;

            case 0x08: /* logout */
                break;

            case 0x09: /* server heartbeat */
                /* do nothing else */
                break;

            case 0x0A:
                result = dissect_order_acknowledgement_message(tvb, batsboe_tree, &offset);
                break;

            case 0x0B: /* order rejected */
                result = dissect_order_rejected_message(tvb, batsboe_tree, &offset);
                break;

            case 0x0C: /* order modified */
                result = dissect_order_modified_message(tvb, batsboe_tree, &offset);
                break;

            case 0x0D: /* order restated */
                result = dissect_order_restated_message(tvb, batsboe_tree, &offset);
                break;

            case 0x0E: /* user modify rejected */
                result = dissect_user_modify_rejected_message(tvb, batsboe_tree, &offset);
                break;

            case 0x0F:
                result = dissect_order_cancelled_message(tvb, batsboe_tree, &offset);
                break;

            case 0x10: /* cancel rejected */
                result = dissect_cancel_rejected_message(tvb, batsboe_tree, &offset);
                break;

            case 0x11: /* order execution */
                result = dissect_order_execution_message(tvb, batsboe_tree, &offset);
                break;

            case 0x12: /* trade cancel or correct */
                break;

            case 0x13: /* replay complete */
                break;

            case 0x14:
                result = dissect_bulk_order(tvb, batsboe_tree, &offset, hdr_message_type);
                break;

            case 0x15:
                result = dissect_bulk_order_ack(tvb, batsboe_tree, &offset);
                break;

            case 0x1C:
                result = dissect_bulk_order(tvb, batsboe_tree, &offset, hdr_message_type);
                break;

            case 0x1D:
                result = dissect_bulk_order_ack_ext(tvb, batsboe_tree, &offset);
                break;

            case 0x37:
                result = dissect_login_request_v2_message(tvb, batsboe_tree, &offset);
                break;
                
            default:
                break;
        }

        offset += hdr_length + 2;
    }

    (void) result; /* TODO */
    return offset;
}

void
proto_reg_handoff_batsboe(void)
{
    heur_dissector_add("tcp", dissect_batsboe, proto_batsboe);
    batsboe_handle = new_create_dissector_handle(dissect_batsboe, proto_batsboe);
    dissector_add_handle("tcp.port", batsboe_handle);
}

void
proto_register_batsboe(void)
{
    static hf_register_info hf[] = {
            { &hf_batsboe_hdr_start_of_message,          { "Start of Message",              "batsboe.start_of_message",         FT_UINT16,  BASE_HEX,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_hdr_message_length,            { "Message Length",                "batsboe.message_length",           FT_UINT16,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_hdr_message_type,              { "Message Type",                  "batsboe.message_type",             FT_UINT8,   BASE_HEX,     boeMessageTypeStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_hdr_matching_unit,             { "Matching Unit",                 "batsboe.matching_unit",            FT_UINT8,   BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_hdr_sequence_number,           { "Sequence Number",               "batsboe.sequence_number",          FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_session_sub_id,                { "Session Sub ID",                "batsboe.session_sub_id",           FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_username,                      { "Username",                      "batsboe.username",                 FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_password,                      { "Password",                      "batsboe.password",                 FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_no_unspecified_unit_replay,    { "No Unspecified Unit Replay",    "batsboe.no_unspecified_unit",      FT_UINT8,   BASE_HEX,     boeNoUnspecifiedUnitReplayStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_number_of_units,               { "Number of Units",               "batsboe.number_of_units",          FT_UINT8,   BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_login_response_status,         { "Login Response Status",         "batsboe.login_response_status",    FT_UINT8,   BASE_HEX,     boeLoginResponseStatusStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_login_response_text,           { "Login Response Text",           "batsboe.login_response_text",      FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_last_received_sequence_number, { "Last Received Sequence Number", "batsboe.last_received_sequence",   FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_transaction_time,              { "Transaction Time",              "batsboe.transaction_time",         FT_UINT64,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_cl_ord_id,                     { "Cl Ord ID",                     "batsboe.cl_ord_id",                FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_cancel_reason,                 { "Cancel Reason",                 "batsboe.cancel_reason",            FT_UINT8,   BASE_HEX,     boeCancelReasonStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_side,                          { "Side",                          "batsboe.side",                     FT_UINT8,   BASE_HEX,     boeSideStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_peg_difference,                { "Peg Difference",                "batsboe.peg_difference",           FT_UINT64,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_price,                         { "Price",                         "batsboe.price",                    FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_exec_inst,                     { "Exec Inst",                     "batsboe.exec_inst",                FT_UINT8,   BASE_HEX,     boeExecInstStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_ord_type,                      { "Ord Type",                      "batsboe.ord_type",                 FT_UINT8,   BASE_HEX,     boeOrdTypeStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_time_in_force,                 { "Time in Force",                 "batsboe.time_in_force",            FT_UINT8,   BASE_HEX,     boeTimeInForceStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_min_qty,                       { "Min Qty",                       "batsboe.min_qty",                  FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_max_remove_pct,                { "Max Remove Pct",                "batsboe.max_remove_pct",           FT_UINT8,   BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_symbol,                        { "Symbol",                        "batsboe.symbol",                   FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_symbol_sfx,                    { "Symbol Sfx",                    "batsboe.symbol_sfx",               FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_currency,                      { "Currency",                      "batsboe.currency",                 FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_idsource,                      { "ID Source",                     "batsboe.idsource",                 FT_UINT8,   BASE_HEX,     boeIdSourceStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_security_id,                   { "Security ID",                   "batsboe.security_id",              FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_security_exchange,             { "Security Exchange",             "batsboe.security_exchange",        FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_capacity,                      { "Capacity",                      "batsboe.capacity",                 FT_UINT8,   BASE_HEX,     boeCapacityStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_contra_capacity,               { "Contra Capacity",               "batsboe.contra_capacity",          FT_UINT8,   BASE_HEX,     boeCapacityStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_cross_flag,                    { "Cross Flag",                    "batsboe.cross_flag",               FT_UINT8,   BASE_HEX,     boeCrossFlagStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_account,                       { "Account",                       "batsboe.account",                  FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_clearing_firm,                 { "Clearing Firm",                 "batsboe.clearing_firm",            FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_clearing_account,              { "Clearing Account",              "batsboe.clearing_account",         FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_display_indicator,             { "Display Indicator",             "batsboe.display_indicator",        FT_UINT8,   BASE_HEX,     boeDisplayIndicatorStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_max_floor,                     { "Max Floor",                     "batsboe.max_floor",                FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_discretion_amount,             { "Discretion Amount",             "batsboe.discretion_amount",        FT_UINT16,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_order_qty,                     { "Order Qty",                     "batsboe.order_qty",                FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_prevent_match,                 { "Prevent Match",                 "batsboe.prevent_match",            FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_maturity_date,                 { "Maturity Date",                 "batsboe.maturity_date",            FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_strike_price,                  { "Strike Price",                  "batsboe.strike_price",             FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_put_or_call,                   { "Put or Call",                   "batsboe.put_or_call",              FT_UINT8,   BASE_HEX,     boePutOrCallStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_open_close,                    { "Open Close",                    "batsboe.open_close",               FT_UINT8,   BASE_HEX,     boeOpenCloseStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_cl_ord_id_batch,               { "Cl Ord ID Batch",               "batsboe.cl_ord_id_batch",          FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_orig_cl_ord_id,                { "Orig Cl Ord ID",                "batsboe.orig_cl_ord_id",           FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_leaves_qty,                    { "Leaves Qty",                    "batsboe.leaves_qty",               FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_last_shares,                   { "Last Shares",                   "batsboe.last_shares",              FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_last_px,                       { "Last Px",                       "batsboe.last_px",                  FT_STRING,  BASE_NONE,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_display_price,                 { "Display Price",                 "batsboe.display_price",            FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_working_price,                 { "Working Price",                 "batsboe.working_price",            FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_base_liquidity_indicator,      { "Base Liquidity Indicator",      "batsboe.base_liquidity_indicator", FT_UINT8,   BASE_HEX,     boeBaseLiquidityIndicatorStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_expire_time,                   { "Expire Time",                   "batsboe.expire_time",              FT_UINT64,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_order_id,                      { "Order ID",                      "batsboe.order_id",                 FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_secondary_order_id,            { "Secondary Order ID",            "batsboe.secondary_order_id",       FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_ccp,                           { "CCP",                           "batsboe.ccp",                      FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_routing_inst,                  { "Routing Inst",                  "batsboe.routing_inst",             FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_bulk_order_ids,                { "Bulk Order IDs",                "batsboe.bulk_order_ids",           FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_bulk_reject_reasons,           { "Bulk Reject Reasons",           "batsboe.bulk_reject_reasons",      FT_UINT8,   BASE_HEX,     boeOrderRejectReasonStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_locate_reqd,                   { "Locate Reqd",                   "batsboe.locate_reqd",              FT_UINT8,   BASE_HEX,     boeLocateReqdStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_cancel_orig_on_reject,         { "Cancel Orig on Reject",         "batsboe.cancel_orig_on_reject",    FT_UINT8,   BASE_HEX,     boeCancelOrigOnRejectStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_order_reject_reason,           { "Order Reject Reason",           "batsboe.order_reject_reason",      FT_UINT8,   BASE_HEX,     boeOrderRejectReasonStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_modify_reject_reason,          { "Modify Reject Reason",          "batsboe.modify_reject_reason",     FT_UINT8,   BASE_HEX,     boeModifyRejectReasonStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_text,                          { "Text",                          "batsboe.text",                     FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_restatement_reason,            { "Restatement Reason",            "batsboe.restatement_reason",       FT_UINT8,   BASE_HEX,     boeRestatementReasonStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_exec_id,                       { "Exec ID",                       "batsboe.exec_id",                  FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_sub_liquidity_indicator,       { "Sub Liquidity Indicator",       "batsboe.sub_liquidity_indicator",  FT_UINT8,   BASE_HEX,     boeSubLiquidityIndicatorStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_access_fee,                    { "Access Fee",                    "batsboe.access_fee",               FT_UINT64,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_contra_broker,                 { "Contra Broker",                 "batsboe.contra_broker",            FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_cancel_reject_reason,          { "Cancel Reject Reason",          "batsboe.cancel_reject_reason",     FT_UINT8,   BASE_HEX,     boeCancelRejectReasonStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_osi_root,                      { "OSI Root",                      "batsboe.osi_root",                 FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_group_cnt,                     { "Group Count",                   "batsboe.group_cnt",                FT_UINT16,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_risk_reset,                    { "Risk Reset",                    "batsboe.risk_reset",               FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_cmta_number,                   { "CMTA Number",                   "batsboe.cmta_number",              FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_bid_short_price,               { "Bid Short Price",               "batsboe.bid_short_price",          FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_bid_order_qty,                 { "Bid Order Qty",                 "batsboe.bid_order_qty",            FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_bid_discretion_amount,         { "Bid Discretion Amount",         "batsboe.bid_discretion_amount",    FT_UINT16,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_bid_open_close,                { "Bid Open Close",                "batsboe.bid_open_close",           FT_UINT8,   BASE_HEX,     boeOpenCloseStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_ask_short_price,               { "Ask Short Price",               "batsboe.ask_short_price",          FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_ask_order_qty,                 { "Ask Order Qty",                 "batsboe.ask_order_qty",            FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_ask_discretion_amount,         { "Ask Discretion Amount",         "batsboe.ask_discretion_amount",    FT_UINT16,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_ask_open_close,                { "Ask Open Close",                "batsboe.ask_open_close",           FT_UINT8,   BASE_HEX,     boeOpenCloseStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_accepted_count,                { "Accepted Count",                "batsboe.accepted_count",           FT_UINT16,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_rejected_count,                { "Rejected Count",                "batsboe.rejected_count",           FT_UINT16,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_corrected_size,                { "Corrected Size",                "batsboe.corrected_size",           FT_UINT32,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_party_id,                      { "Party ID",                      "batsboe.party_id",                 FT_STRING,  BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_batsboe_attributed_quote,              { "Attributed Quote",              "batsboe.attributed_quote",         FT_UINT8,   BASE_HEX,     boeAttributedQuoteStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_ext_exec_inst,                 { "Ext Exec Inst",                 "batsboe.ext_exec_inst",            FT_UINT8,   BASE_HEX,     boeExtExecInstStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_party_role,                    { "Party Role",                    "batsboe.party_role",               FT_UINT8,   BASE_HEX,     boePartyRoleStrings, 0x0, NULL, HFILL } },
            { &hf_batsboe_large_size,                    { "Large Size" ,                   "batsboe.large_size",               FT_UINT64,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
            &ett_batsboe,
            &ett_batsboe_return_bitfields,
    };

    proto_batsboe = proto_register_protocol (
        "BATS Binary Order Entry", /* name */
        "BATS BOE",            /* short name */
        "batsboe"          /* abbrev */
        );

    proto_register_field_array(proto_batsboe, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    prefs_register_protocol(proto_batsboe, NULL);
}
