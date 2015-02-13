/* packet-mcastpitch.c
 *
 * Routines for BATS Multicast PITCH.
 * Copyright 2010-2015, Eric Crampton
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

#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include <epan/packet.h>
#include <epan/prefs.h>

int proto_mcastpitch = -1;
static dissector_handle_t mcastpitch_handle;

static int hf_mcastpitch_hdr_length               = -1;
static int hf_mcastpitch_hdr_count                = -1;
static int hf_mcastpitch_hdr_unit                 = -1;
static int hf_mcastpitch_hdr_sequence             = -1;
static int hf_mcastpitch_msg_length               = -1;
static int hf_mcastpitch_msg_type                 = -1;
static int hf_mcastpitch_time                     = -1;
static int hf_mcastpitch_time_offset              = -1;
static int hf_mcastpitch_order_id                 = -1;
static int hf_mcastpitch_side                     = -1;
static int hf_mcastpitch_long_quantity            = -1;
static int hf_mcastpitch_quantity8                = -1;
static int hf_mcastpitch_symbol6                  = -1;
static int hf_mcastpitch_long_price               = -1;
static int hf_mcastpitch_short_quantity           = -1;
static int hf_mcastpitch_short_price              = -1;
static int hf_mcastpitch_executed_shares          = -1;
static int hf_mcastpitch_execution_id             = -1;
static int hf_mcastpitch_trade_id                 = -1;
static int hf_mcastpitch_remaining_shares         = -1;
static int hf_mcastpitch_long_canceled_shares     = -1;
static int hf_mcastpitch_short_canceled_shares    = -1;
static int hf_mcastpitch_symbol8                  = -1;
static int hf_mcastpitch_add_flags                = -1;
static int hf_mcastpitch_osi_symbol               = -1;
static int hf_mcastpitch_session_sub_id           = -1;
static int hf_mcastpitch_username                 = -1;
static int hf_mcastpitch_filler                   = -1;
static int hf_mcastpitch_password                 = -1;
static int hf_mcastpitch_login_status             = -1;
static int hf_mcastpitch_trading_status           = -1;
static int hf_mcastpitch_options_symbol_condition = -1;
static int hf_mcastpitch_reg_sho_action           = -1;
static int hf_mcastpitch_retail_price_improvement = -1;
static int hf_mcastpitch_reserved1                = -1;
static int hf_mcastpitch_reserved2                = -1;
static int hf_mcastpitch_auction_type             = -1;
static int hf_mcastpitch_reference_price          = -1;
static int hf_mcastpitch_buy_shares               = -1;
static int hf_mcastpitch_sell_shares              = -1;
static int hf_mcastpitch_indicative_price         = -1;
static int hf_mcastpitch_auction_only_price       = -1;
static int hf_mcastpitch_sequence                 = -1;
static int hf_mcastpitch_order_count              = -1;
static int hf_mcastpitch_gap_response_status      = -1;
static int hf_mcastpitch_spin_response_status     = -1;
static int hf_mcastpitch_status                   = -1;
static int hf_mcastpitch_unit                     = -1;
static int hf_mcastpitch_count                    = -1;
static int hf_mcastpitch_measurement_type         = -1;
static int hf_mcastpitch_begin_time               = -1;
static int hf_mcastpitch_end_time                 = -1;
static int hf_mcastpitch_minimum                  = -1;
static int hf_mcastpitch_maximum                  = -1;
static int hf_mcastpitch_average                  = -1;
static int hf_mcastpitch_standard_deviation       = -1;
static int hf_mcastpitch_mode                     = -1;
static int hf_mcastpitch_99_9_percentile          = -1;
static int hf_mcastpitch_99_percentile            = -1;
static int hf_mcastpitch_95_percentile            = -1;
static int hf_mcastpitch_90_percentile            = -1;
static int hf_mcastpitch_75_percentile            = -1;
static int hf_mcastpitch_50_percentile            = -1;
static int hf_mcastpitch_25_percentile            = -1;
static int hf_mcastpitch_trade_time               = -1;
static int hf_mcastpitch_exec_venue               = -1;
static int hf_mcastpitch_traded_currency          = -1;
static int hf_mcastpitch_trade_report_flags       = -1;
static int hf_mcastpitch_participant_id           = -1;
static int hf_mcastpitch_trade_flags              = -1;
static int hf_mcastpitch_execution_flags          = -1;
static int hf_mcastpitch_statistic_type           = -1;
static int hf_mcastpitch_price_determination      = -1;

static gint ett_mcastpitch = -1;

static expert_field ei_mcastpitch_out_of_sequence = EI_INIT;

static const gint SEQUENCED_UNIT_HEADER_LEN                   = 8;
static const gint LOGIN_MESSAGE_LEN                           = 22;
static const gint LOGIN_RESPONSE_MESSAGE_LEN                  = 3;
static const gint GAP_REQUEST_MESSAGE_LEN                     = 9;
static const gint GAP_RESPONSE_MESSAGE_LEN                    = 10;
static const gint TIME_MESSAGE_LEN                            = 6;
static const gint ADD_ORDER_LONG_EU_MESSAGE_LEN               = 35;
static const gint ADD_ORDER_LONG_US_MESSAGE_LEN               = 34;
static const gint ADD_ORDER_SHORT_EU_MESSAGE_LEN              = 25;
static const gint ADD_ORDER_SHORT_US_MESSAGE_LEN              = 26;
static const gint ORDER_EXECUTED_EU_MESSAGE_LEN               = 29;
static const gint ORDER_EXECUTED_US_MESSAGE_LEN               = 26;
static const gint ORDER_EXECUTED_AT_PRICE_SIZE_EU_MESSAGE_LEN = 41;
static const gint ORDER_EXECUTED_AT_PRICE_SIZE_US_MESSAGE_LEN = 38;
static const gint REDUCE_SIZE_LONG_MESSAGE_LEN                = 18;
static const gint REDUCE_SIZE_SHORT_MESSAGE_LEN               = 16;
static const gint MODIFY_ORDER_LONG_EU_MESSAGE_LEN            = 26;
static const gint MODIFY_ORDER_LONG_US_MESSAGE_LEN            = 27;
static const gint MODIFY_ORDER_SHORT_EU_MESSAGE_LEN           = 18;
static const gint MODIFY_ORDER_SHORT_US_MESSAGE_LEN           = 19;
static const gint DELETE_ORDER_MESSAGE_LEN                    = 14;
static const gint TRADE_LONG_EU_MESSAGE_LEN                   = 47;
static const gint TRADE_LONG_US_MESSAGE_LEN                   = 41;
static const gint TRADE_SHORT_EU_MESSAGE_LEN                  = 37;
static const gint TRADE_SHORT_US_MESSAGE_LEN                  = 33;
static const gint TRADE_BREAK_MESSAGE_LEN                     = 14;
static const gint TRADE_REPORT_MESSAGE_LEN                    = 64;
static const gint END_OF_SESSION_MESSAGE_LEN                  = 6;
static const gint SYMBOL_MAPPING_MESSAGE_LEN                  = 30;
static const gint TRADING_STATUS_MESSAGE_LEN                  = 18;
static const gint ADD_ORDER_EXPANDED_US_MESSAGE_LEN           = 36;
static const gint ADD_ORDER_EXPANDED_EU_MESSAGE_LEN           = 40;
static const gint TRADE_EXPANDED_MESSAGE_LEN                  = 43;
static const gint SPIN_IMAGE_AVAILABLE_MESSAGE_LEN            = 6;
static const gint SPIN_REQUEST_MESSAGE_LEN                    = 6;
static const gint SPIN_RESPONSE_MESSAGE_LEN                   = 11;
static const gint SPIN_FINISHED_MESSAGE_LEN                   = 6;
static const gint AUCTION_UPDATE_MESSAGE_LEN                  = 47;
static const gint AUCTION_SUMMARY_MESSAGE_LEN                 = 27;
static const gint UNIT_CLEAR_MESSAGE_LEN                      = 6;
static const gint RETAIL_PRICE_IMPROVEMENT_MESSAGE_LEN        = 15;
static const gint LATENCY_STAT_MESSAGE_LEN                    = 112;
static const gint STATISTICS_MESSAGE_LEN                      = 24;

static const value_string login_response_status[] = {
    { 'A', "'A' Login Accepted" },
    { 'N', "'N' Not Authorized (Invalid Username/Password)" },
    { 'B', "'B' Session in Use" },
    { 'S', "'S' Invalid Session" },
    { 0, NULL },
};

static const value_string gap_response_status[] = {
    { 'A', "'A' Accepted" },
    { 'O', "'O' Out of Range" },
    { 'D', "'D' Daily Gap Request Allocation Exhausted" },
    { 'M', "'M' Minute Gap Request Allocation Exhausted" },
    { 'S', "'S' Second Gap Request Allocation Exhausted" },
    { 'C', "'C' Count Request Limit Exceeded" },
    { 'I', "'I' Invalid Unit" },
    { 'U', "'U' Unit Currently Unavailable" },
    { 0, NULL },
};

static const value_string spin_response_status[] = {
    { 'A', "'A' Accepted" },
    { 'O', "'O' Out of Range" },
    { 'S', "'S' Spin Already in Progress" },
    { 0, NULL },
};

static const value_string options_symbol_condition[] = {
    { 'N', "'N' Normal" },
    { 'C', "'C' Closing Only" },
    { 0, NULL },
};

static const value_string auction_type[] = {
    { 'O', "'O' Opening Auction" },
    { 'C', "'C' Closing Auction" },
    { 'H', "'H' Halt Auction" },
    { 'I', "'I' IPO Auction" },
    { 'V', "'V' Volatility Auction" },
    { 0, NULL },
};
 
static const value_string statistic_type[] = {
    { 'C', "'C' Closing Price" },
    { 'H', "'H' High Price" },
    { 'L', "'L' Low Price" },
    { 'O', "'O' Opening Price" },
    { 'P', "'P' Previous Closing Price" },
    { 0, NULL },
};

static const value_string price_determination[] = {
    { '0', "'0' Normal" },
    { '1', "'1' Manual" },
    { 0, NULL },
};

static const value_string trading_status[] = {
    { 'T', "'T' Trading" },
    { 'H', "'H' Halted" },
    { 'Q', "'Q' Quote-Only" },
    { 'R', "'R' Off-Book Reporting" },
    { 'C', "'C' Closed" },
    { 'S', "'S'Suspension" },
    { 'N', "'N' No Reference Price" },
    { 'O', "'O' Opening Auction" },
    { 'E', "'E' Closing Auction" },
    { 'V', "'V'Volatility Interruption" },
    { 'M', "'M' Market Order Imbalance" },
    { 'P', "'P' Price Monitoring Extension" },
    { 'A', "'A' Accepting Orders for Queuing" },
    { 0, NULL },
};

static const value_string reg_sho_action[] = {
    { '0', "'0' No Price Test in Effect" },
    { '1', "'1' Reg SHO Price Test Restriction in Effect" },
    { 0, NULL },
};

static const value_string retail_price_improvement[] = {
    { 'B', "'B' Buy Side RPI" },
    { 'S', "'S' Sell Side RPI" },
    { 'A', "'A' Buy and Sell Side RPI" },
    { 'N', "'N' No RPI" },
    { 0, NULL },
};

#define MCP_OUT_OF_SEQUENCE 0x0001

typedef struct mcp_frame_data{
    guint32 expected_sequence;
    guint16 flags;
} mcp_frame_data_t;

typedef struct mcp_analysis {
    /* Next expected sequence number. */     
    guint32 next_sequence;

    /* This pointer is NULL or points to a mcp_frame_data struct if this packet has "interesting" properties,
     * e.g., out-of-sequence.
     */ 
    mcp_frame_data_t *fd;

    /* This structure contains a tree of "interesting" frame data keyed by the frame number. */
    wmem_tree_t *frame_table;
} mcp_analysis_t;

static void
proto_tree_add_short_price(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    guint16 value = tvb_get_letohs(tvb, offset);
    
    proto_tree_add_string_format_value(
            tree, hf, tvb, offset, 2, "",
            "%u = %u.%02u", value, value / 100, value % 100);
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
proto_tree_add_base36(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    static char BASE36_DIGITS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char buffer[13]; /* order IDs are 12 bytes, execution IDs are 9 bytes */
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
            tree, hf, tvb, offset, 8, buffer,
            "%s", buffer);
}

static void
proto_tree_add_ssm(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    guint32 ssm = tvb_get_letohl(tvb, offset);
    int hours = ssm / 60 / 60, minutes = (ssm / 60) % 60, seconds = ssm % 60;

    proto_tree_add_string_format_value(
            tree, hf, tvb, offset, 4, "",
            "%u = %02d:%02d:%02d", ssm, hours, minutes, seconds);
}

static guint8
dissect_login_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *m_item;
    proto_tree *m_tree;

    if (tvb_length_remaining(tvb, *offset) < LOGIN_MESSAGE_LEN) {
        return 0;
    }
    
    m_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, LOGIN_MESSAGE_LEN, "Login");

    m_tree = proto_item_add_subtree(m_item, ett_mcastpitch);

    proto_tree_add_item(m_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_session_sub_id, tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_username,       tvb, *offset + 6,  4, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_filler,         tvb, *offset + 10, 2, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_password,       tvb, *offset + 12, 10, TRUE);
    
    *offset = *offset + LOGIN_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_login_response_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *m_item;
    proto_tree *m_tree;

    if (tvb_length_remaining(tvb, *offset) < LOGIN_RESPONSE_MESSAGE_LEN) {
        return 0;
    }
    
    m_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, LOGIN_RESPONSE_MESSAGE_LEN, "Login Response");

    m_tree = proto_item_add_subtree(m_item, ett_mcastpitch);

    proto_tree_add_item(m_tree, hf_mcastpitch_msg_length,   tvb, *offset,      1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_msg_type,     tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_login_status, tvb, *offset + 2,  1, TRUE);
    
    *offset = *offset + LOGIN_RESPONSE_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_gap_request_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *m_item;
    proto_tree *m_tree;

    if (tvb_length_remaining(tvb, *offset) < GAP_REQUEST_MESSAGE_LEN) {
        return 0;
    }
    
    m_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, GAP_REQUEST_MESSAGE_LEN, "Gap Request");

    m_tree = proto_item_add_subtree(m_item, ett_mcastpitch);

    proto_tree_add_item(m_tree, hf_mcastpitch_msg_length, tvb, *offset,      1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_msg_type,   tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_unit,       tvb, *offset + 2,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_sequence,   tvb, *offset + 3,  4, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_count,      tvb, *offset + 7,  2, TRUE);
    
    *offset = *offset + GAP_REQUEST_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_gap_response_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *m_item;
    proto_tree *m_tree;

    if (tvb_length_remaining(tvb, *offset) < GAP_RESPONSE_MESSAGE_LEN) {
        return 0;
    }
    
    m_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, GAP_RESPONSE_MESSAGE_LEN, "Gap Response");

    m_tree = proto_item_add_subtree(m_item, ett_mcastpitch);

    proto_tree_add_item(m_tree, hf_mcastpitch_msg_length,          tvb, *offset,      1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_msg_type,            tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_unit,                tvb, *offset + 2,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_sequence,            tvb, *offset + 3,  4, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_count,               tvb, *offset + 7,  2, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_gap_response_status, tvb, *offset + 9,  1, TRUE);
    
    *offset = *offset + GAP_RESPONSE_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_time_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *m_item;
    proto_tree *m_tree;

    if (tvb_length_remaining(tvb, *offset) < TIME_MESSAGE_LEN) {
        return 0;
    }
    
    m_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, TIME_MESSAGE_LEN, "Time");

    m_tree = proto_item_add_subtree(m_item, ett_mcastpitch);

    proto_tree_add_item(m_tree, hf_mcastpitch_msg_length, tvb, *offset,     1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_msg_type,   tvb, *offset + 1, 1, TRUE);
    proto_tree_add_ssm (m_tree, hf_mcastpitch_time,       tvb, *offset + 2);
    
    *offset = *offset + TIME_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_add_order_long_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    
    if (tvb_length_remaining(tvb, *offset) < ADD_ORDER_LONG_US_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, ADD_ORDER_LONG_US_MESSAGE_LEN, "Add Order (Long)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,   tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,      tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_side,          tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_long_quantity, tvb, *offset + 15, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol6,       tvb, *offset + 19, 6, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,    tvb, *offset + 25);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_add_flags,     tvb, *offset + 33, 1, TRUE);
    
    *offset = *offset + ADD_ORDER_LONG_US_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_add_order_long_eu_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    
    if (tvb_length_remaining(tvb, *offset) < ADD_ORDER_LONG_EU_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, ADD_ORDER_LONG_EU_MESSAGE_LEN, "Add Order (Long)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,   tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,      tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_side,          tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_long_quantity, tvb, *offset + 15, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol8,       tvb, *offset + 19, 8, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,    tvb, *offset + 27);

    *offset = *offset + ADD_ORDER_LONG_EU_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_add_order_short_message(tvbuff_t *tvb, proto_tree *tree, guint8 msg_length, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    gboolean us_format;
    
    if (msg_length == ADD_ORDER_SHORT_EU_MESSAGE_LEN) {
        us_format = FALSE;
    }
    else if (msg_length == ADD_ORDER_SHORT_US_MESSAGE_LEN) {
        us_format = TRUE;
    }
    else {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, msg_length, "Add Order (Short)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36     (msg_tree, hf_mcastpitch_order_id,       tvb, *offset + 6);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_side,           tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_short_quantity, tvb, *offset + 15, 2, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_symbol6,        tvb, *offset + 17, 6, TRUE);
    proto_tree_add_short_price(msg_tree, hf_mcastpitch_short_price,    tvb, *offset + 23);

    if (us_format) {
        proto_tree_add_item(msg_tree, hf_mcastpitch_add_flags, tvb, *offset + 25, 1, TRUE);
    }
    
    *offset = *offset + msg_length;
    
    return 1;
}

static guint8
dissect_order_executed_message(tvbuff_t *tvb, proto_tree *tree, guint8 msg_length, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    gboolean us_format;
    
    if (msg_length == ORDER_EXECUTED_EU_MESSAGE_LEN) {
        us_format = FALSE;
    }
    else if (msg_length == ORDER_EXECUTED_US_MESSAGE_LEN) {
        us_format = TRUE;
    }
    else {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, msg_length, "Order Executed");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_length,      tvb, *offset,      1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_type,        tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_time_offset,     tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36(msg_tree, hf_mcastpitch_order_id,        tvb, *offset + 6);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_executed_shares, tvb, *offset + 14, 4, TRUE);
    proto_tree_add_base36(msg_tree, hf_mcastpitch_execution_id,    tvb, *offset + 18);

    if (!us_format) {
        proto_tree_add_item(msg_tree, hf_mcastpitch_execution_flags, tvb, *offset + 26, 3, TRUE);
    }

    *offset = *offset + msg_length;
    
    return 1;
}

static guint8
dissect_order_executed_at_price_size_message(tvbuff_t *tvb, proto_tree *tree, guint8 msg_length, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    gboolean us_format;
    
    if (msg_length == ORDER_EXECUTED_AT_PRICE_SIZE_EU_MESSAGE_LEN) {
        us_format = FALSE;
    }
    else if (msg_length == ORDER_EXECUTED_AT_PRICE_SIZE_US_MESSAGE_LEN) {
        us_format = TRUE;
    }
    else {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, msg_length, "Order Executed at Price/Size");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,       tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,         tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,      tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,         tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_executed_shares,  tvb, *offset + 14, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_remaining_shares, tvb, *offset + 18, 4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_execution_id,     tvb, *offset + 22);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,       tvb, *offset + 30);

    if (!us_format) {
        proto_tree_add_item(msg_tree, hf_mcastpitch_execution_flags, tvb, *offset + 38, 3, TRUE);
    }

    *offset = *offset + msg_length;
    
    return 1;
}

static guint8
dissect_reduce_size_long_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < REDUCE_SIZE_LONG_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, REDUCE_SIZE_LONG_MESSAGE_LEN, "Reduce Size (Long)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_length,           tvb, *offset,      1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_type,             tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_time_offset,          tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36(msg_tree, hf_mcastpitch_order_id,             tvb, *offset + 6);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_long_canceled_shares, tvb, *offset + 14, 4, TRUE);

    *offset = *offset + REDUCE_SIZE_LONG_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_reduce_size_short_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < REDUCE_SIZE_SHORT_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, REDUCE_SIZE_SHORT_MESSAGE_LEN, "Reduce Size (Short)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_length,            tvb, *offset,      1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_type,              tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_time_offset,           tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36(msg_tree, hf_mcastpitch_order_id,              tvb, *offset + 6);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_short_canceled_shares, tvb, *offset + 14, 2, TRUE);

    *offset = *offset + REDUCE_SIZE_SHORT_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_modify_order_long_message(tvbuff_t *tvb, proto_tree *tree, guint8 msg_length, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    gboolean us_format;

    if (msg_length == MODIFY_ORDER_LONG_EU_MESSAGE_LEN) {
        us_format = FALSE;
    }
    else if (msg_length == MODIFY_ORDER_LONG_US_MESSAGE_LEN) {
        us_format = TRUE;
    }
    else {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, msg_length, "Modify Order (Long)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,   tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,      tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_long_quantity, tvb, *offset + 14, 4, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,    tvb, *offset + 18);

    if (us_format) {
        proto_tree_add_item(msg_tree, hf_mcastpitch_add_flags, tvb, *offset + 26, 1, TRUE);
    }
    
    *offset = *offset + msg_length;
    
    return 1;
}

static guint8
dissect_modify_order_short_message(tvbuff_t *tvb, proto_tree *tree, guint8 msg_length, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    gboolean us_format;

    if (msg_length == MODIFY_ORDER_SHORT_EU_MESSAGE_LEN) {
        us_format = FALSE;
    }
    else if (msg_length == MODIFY_ORDER_SHORT_US_MESSAGE_LEN) {
        us_format = TRUE;
    }
    else {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, msg_length, "Modify Order (Short)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36     (msg_tree, hf_mcastpitch_order_id,       tvb, *offset + 6);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_short_quantity, tvb, *offset + 14, 2, TRUE);
    proto_tree_add_short_price(msg_tree, hf_mcastpitch_short_price,    tvb, *offset + 16);

    if (us_format) {
        proto_tree_add_item(msg_tree, hf_mcastpitch_add_flags, tvb, *offset + 18, 1, TRUE);
    }
    
    *offset = *offset + msg_length;
    
    return 1;
}

static guint8
dissect_delete_order_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < DELETE_ORDER_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, DELETE_ORDER_MESSAGE_LEN, "Delete Order");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_length,            tvb, *offset,      1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_type,              tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_time_offset,           tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36(msg_tree, hf_mcastpitch_order_id,              tvb, *offset + 6);

    *offset = *offset + DELETE_ORDER_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_trade_long_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < TRADE_LONG_US_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, TRADE_LONG_US_MESSAGE_LEN, "Trade (Long)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,   tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,      tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_side,          tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_long_quantity, tvb, *offset + 15, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol6,       tvb, *offset + 19, 6, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,    tvb, *offset + 25);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_execution_id,  tvb, *offset + 33);

    *offset = *offset + TRADE_LONG_US_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_trade_long_eu_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < TRADE_LONG_EU_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, TRADE_LONG_EU_MESSAGE_LEN, "Trade (Long)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,   tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,      tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_side,          tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_long_quantity, tvb, *offset + 15, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol8,       tvb, *offset + 19, 8, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,    tvb, *offset + 27);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_execution_id,  tvb, *offset + 35);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_trade_flags,   tvb, *offset + 43, 4, TRUE);

    *offset = *offset + TRADE_LONG_EU_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_trade_short_message(tvbuff_t *tvb, proto_tree *tree, guint8 msg_length, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    gboolean us_format;

    if (msg_length == TRADE_SHORT_EU_MESSAGE_LEN) {
        us_format = FALSE;
    }
    else if (msg_length == TRADE_SHORT_US_MESSAGE_LEN) {
        us_format = TRUE;
    }
    else {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, msg_length, "Trade (Short)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36     (msg_tree, hf_mcastpitch_order_id,       tvb, *offset + 6);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_side,           tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_short_quantity, tvb, *offset + 15, 2, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_symbol6,        tvb, *offset + 17, 6, TRUE);
    proto_tree_add_short_price(msg_tree, hf_mcastpitch_short_price,    tvb, *offset + 23);
    proto_tree_add_base36     (msg_tree, hf_mcastpitch_execution_id,   tvb, *offset + 25);

    if (!us_format) {
        proto_tree_add_item   (msg_tree, hf_mcastpitch_trade_flags,    tvb, *offset + 33, 4, TRUE);
    }

    *offset = *offset + msg_length;
    
    return 1;
}

static guint8
dissect_trade_break_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < TRADE_BREAK_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, TRADE_BREAK_MESSAGE_LEN, "Trade Break");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,     1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1, 1, TRUE);
    proto_tree_add_item  (msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2, 4, TRUE);
    proto_tree_add_base36(msg_tree, hf_mcastpitch_execution_id,   tvb, *offset + 6);

    *offset = *offset + TRADE_BREAK_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_trade_report_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < TRADE_REPORT_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, TRADE_REPORT_MESSAGE_LEN, "Trade Report");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_length,         tvb, *offset,      1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_type,           tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_time_offset,        tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_quantity8,          tvb, *offset + 6,  8, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_symbol8,            tvb, *offset + 14, 8, TRUE);
    proto_tree_add_long_price (msg_tree, hf_mcastpitch_long_price,         tvb, *offset + 22);
    proto_tree_add_base36     (msg_tree, hf_mcastpitch_trade_id,           tvb, *offset + 30);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_trade_time,         tvb, *offset + 38, 8, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_exec_venue,         tvb, *offset + 46, 4, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_traded_currency,    tvb, *offset + 50, 3, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_trade_report_flags, tvb, *offset + 53, 11,TRUE);

    *offset = *offset + TRADE_REPORT_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_statistics_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < STATISTICS_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, STATISTICS_MESSAGE_LEN, "Statistics");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_length,          tvb, *offset,      1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_msg_type,            tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_time_offset,         tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_symbol8,             tvb, *offset + 6,  8, TRUE);
    proto_tree_add_long_price (msg_tree, hf_mcastpitch_long_price,          tvb, *offset + 14);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_statistic_type,      tvb, *offset + 22, 1, TRUE);
    proto_tree_add_item       (msg_tree, hf_mcastpitch_price_determination, tvb, *offset + 23, 1, TRUE);

    *offset = *offset + STATISTICS_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_end_of_session_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < END_OF_SESSION_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, END_OF_SESSION_MESSAGE_LEN, "End Of Session");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,     1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1, 1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2, 4, TRUE);

    *offset = *offset + END_OF_SESSION_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_symbol_mapping_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < SYMBOL_MAPPING_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, SYMBOL_MAPPING_MESSAGE_LEN, "Symbol Mapping");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,               tvb, *offset,      1,  TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,                 tvb, *offset + 1,  1,  TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_symbol6,                  tvb, *offset + 2,  6,  TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_osi_symbol,               tvb, *offset + 8,  21, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_options_symbol_condition, tvb, *offset + 29, 1,  TRUE);

    *offset = *offset + SYMBOL_MAPPING_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_add_order_expanded_message(tvbuff_t *tvb, proto_tree *tree, guint8 msg_length, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;
    gboolean expanded;

    if (msg_length == ADD_ORDER_EXPANDED_US_MESSAGE_LEN) {
        expanded = FALSE;
    }
    else if (msg_length == ADD_ORDER_EXPANDED_EU_MESSAGE_LEN) {
        expanded = TRUE;
    }
    else {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, msg_length, "Add Order (Expanded)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,   tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,      tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_side,          tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_long_quantity, tvb, *offset + 15, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol8,       tvb, *offset + 19, 8, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,    tvb, *offset + 27);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_add_flags,     tvb, *offset + 35, 1, TRUE);

    if (expanded) {
        proto_tree_add_item(msg_tree, hf_mcastpitch_participant_id, tvb, *offset + 36, 4, TRUE);
    }

    *offset = *offset + msg_length;

    return 1;
}

static guint8
dissect_trade_expanded_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < TRADE_EXPANDED_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, TRADE_EXPANDED_MESSAGE_LEN, "Trade (Expanded)");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,   tvb, *offset + 2,  4, TRUE);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_order_id,      tvb, *offset + 6);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_side,          tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_long_quantity, tvb, *offset + 15, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol8,       tvb, *offset + 19, 8, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,    tvb, *offset + 27);
    proto_tree_add_base36    (msg_tree, hf_mcastpitch_execution_id,  tvb, *offset + 35);

    *offset = *offset + TRADE_EXPANDED_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_trading_status_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < TRADING_STATUS_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, TRADING_STATUS_MESSAGE_LEN, "Trading Status");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_symbol8,        tvb, *offset + 6,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_trading_status, tvb, *offset + 14, 1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_reg_sho_action, tvb, *offset + 15, 1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_reserved1,      tvb, *offset + 16, 1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_reserved2,      tvb, *offset + 17, 1, TRUE);

    *offset = *offset + TRADING_STATUS_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_spin_image_available_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < SPIN_IMAGE_AVAILABLE_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, SPIN_IMAGE_AVAILABLE_MESSAGE_LEN, "Spin Image Available");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_sequence,       tvb, *offset + 2,  4, TRUE);

    *offset = *offset + SPIN_IMAGE_AVAILABLE_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_spin_request_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < SPIN_REQUEST_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, SPIN_REQUEST_MESSAGE_LEN, "Spin Request");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_sequence,       tvb, *offset + 2,  4, TRUE);

    *offset = *offset + SPIN_REQUEST_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_spin_response_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < SPIN_RESPONSE_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, SPIN_RESPONSE_MESSAGE_LEN, "Spin Response");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,           tvb, *offset,      1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,             tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_sequence,             tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_order_count,          tvb, *offset + 6,  4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_spin_response_status, tvb, *offset + 10, 1, TRUE);

    *offset = *offset + SPIN_RESPONSE_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_spin_finished_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < SPIN_FINISHED_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, SPIN_FINISHED_MESSAGE_LEN, "Spin Finished");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_sequence,       tvb, *offset + 2,  4, TRUE);

    *offset = *offset + SPIN_FINISHED_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_latency_stat_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < LATENCY_STAT_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, LATENCY_STAT_MESSAGE_LEN, "Latency Stat");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,         tvb, *offset,       1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,           tvb, *offset + 1,   1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_measurement_type,   tvb, *offset + 2,   1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_hdr_unit,           tvb, *offset + 3,   1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_begin_time,         tvb, *offset + 4,   4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_end_time,           tvb, *offset + 8,   4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_order_count,        tvb, *offset + 12,  4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_minimum,            tvb, *offset + 16,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_maximum,            tvb, *offset + 24,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_average,            tvb, *offset + 32,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_standard_deviation, tvb, *offset + 40,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_mode,               tvb, *offset + 48,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_99_9_percentile,    tvb, *offset + 56,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_99_percentile,      tvb, *offset + 64,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_95_percentile,      tvb, *offset + 72,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_90_percentile,      tvb, *offset + 80,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_75_percentile,      tvb, *offset + 88,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_50_percentile,      tvb, *offset + 96,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_25_percentile,      tvb, *offset + 104, 8, TRUE);

    *offset = *offset + LATENCY_STAT_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_auction_update_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < AUCTION_UPDATE_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, AUCTION_UPDATE_MESSAGE_LEN, "Auction Update");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,         tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,           tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,        tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol8,            tvb, *offset + 6,  8, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_auction_type,       tvb, *offset + 14, 1, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_reference_price,    tvb, *offset + 15);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_buy_shares,         tvb, *offset + 23, 4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_sell_shares,        tvb, *offset + 27, 4, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_indicative_price,   tvb, *offset + 31);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_auction_only_price, tvb, *offset + 39);

    *offset = *offset + AUCTION_UPDATE_MESSAGE_LEN;
    
    return 1;
}

static guint8
dissect_auction_summary_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < AUCTION_SUMMARY_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, AUCTION_SUMMARY_MESSAGE_LEN, "Auction Summary");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_length,         tvb, *offset,      1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_msg_type,           tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_time_offset,        tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_symbol8,            tvb, *offset + 6,  8, TRUE);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_auction_type,       tvb, *offset + 14, 1, TRUE);
    proto_tree_add_long_price(msg_tree, hf_mcastpitch_long_price,         tvb, *offset + 15);
    proto_tree_add_item      (msg_tree, hf_mcastpitch_executed_shares,    tvb, *offset + 23, 4, TRUE);

    *offset = *offset + AUCTION_SUMMARY_MESSAGE_LEN;
    
    return 1;
}

static mcp_analysis_t *
mcp_analysis_get_conversation_data(packet_info *pinfo)
{
    conversation_t *conv;
    mcp_analysis_t *mcpa;

    /* By using the source and destination ports we end up with separate conversation for each MCP unit */
    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    if (!conv) {
        /* New conversation, initialise analysis data */
        conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
        mcpa = (mcp_analysis_t *)wmem_alloc(wmem_file_scope(), sizeof(mcp_analysis_t));
        mcpa->next_sequence = 0;
        mcpa->fd = NULL;
        mcpa->frame_table = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_mcastpitch, (void *)mcpa);
    }
    else {
        /* Use existing conversation */
        mcpa = (mcp_analysis_t *)conversation_get_proto_data(conv, proto_mcastpitch);
        if (!mcpa) {
            mcpa = (mcp_analysis_t *)wmem_alloc(wmem_file_scope(), sizeof(mcp_analysis_t));
            mcpa->next_sequence = 0;
            mcpa->fd = NULL;
            mcpa->frame_table = wmem_tree_new(wmem_file_scope());
            conversation_add_proto_data(conv, proto_mcastpitch, (void *)mcpa);
        }
    }

    return mcpa;
}

static void
mcp_analysis_get_frame_data(guint32 frame, gboolean createflag, mcp_analysis_t *mcpa)
{
    if (!mcpa) {
        return;
    }
    
    mcpa->fd = (mcp_frame_data_t *)wmem_tree_lookup32(mcpa->frame_table, frame);
    if ((!mcpa->fd) && createflag) {
        mcpa->fd = wmem_new0(wmem_file_scope(), struct mcp_frame_data);
        wmem_tree_insert32(mcpa->frame_table, frame, (void *)mcpa->fd);
    }
}

static guint8
dissect_unit_clear_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < UNIT_CLEAR_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, UNIT_CLEAR_MESSAGE_LEN, "Unit Clear");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,     1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1, 1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2, 4, TRUE);

    *offset = *offset + UNIT_CLEAR_MESSAGE_LEN;

    return 1;
}

static guint8
dissect_retail_price_improvement_message(tvbuff_t *tvb, proto_tree *tree, int *offset)
{
    proto_item *msg_item;
    proto_tree *msg_tree;

    if (tvb_length_remaining(tvb, *offset) < RETAIL_PRICE_IMPROVEMENT_MESSAGE_LEN) {
        return 0;
    }

    msg_item = proto_tree_add_protocol_format(
            tree, proto_mcastpitch, tvb,
            *offset, RETAIL_PRICE_IMPROVEMENT_MESSAGE_LEN, "Retail Price Improvement");

    msg_tree = proto_item_add_subtree(msg_item, ett_mcastpitch);

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,               tvb, *offset,      1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,                 tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_time_offset,              tvb, *offset + 2,  4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_symbol8,                  tvb, *offset + 6,  8, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_retail_price_improvement, tvb, *offset + 14, 1, TRUE);

    *offset = *offset + RETAIL_PRICE_IMPROVEMENT_MESSAGE_LEN;

    return 1;
}

static int
dissect_mcastpitch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint bytes, offset = 0;
    proto_item *item, *sequence_item;
    proto_tree *mcastpitch_tree;
    guint16 hdr_length;
    guint8 hdr_count;
    guint32 hdr_sequence;
    mcp_analysis_t *mcpa;
    
    bytes = tvb_length_remaining(tvb, 0);

    if (bytes < SEQUENCED_UNIT_HEADER_LEN) {
        /* There aren't enough bytes to even decode the header. This must be malformed data. */
        return offset;
    }

    hdr_length   = tvb_get_letohs(tvb, 0);
    hdr_count    = tvb_get_guint8(tvb, 2);
    hdr_sequence = tvb_get_letohl(tvb, 4);

    if (bytes != hdr_length) {
        /* The number of bytes in the datagram doesn't match what the header says it should be. This
           must be malformed data. */
        return offset;
    }

    /* Retrieve mcp analysis data for this unit */
    mcpa = mcp_analysis_get_conversation_data(pinfo);

    /* Perform the MCP packet analysis (but only on the first run through the capture) */
    if (!pinfo->fd->flags.visited) {
        if (pinfo->ipproto == IP_PROTO_UDP && mcpa->next_sequence && mcpa->next_sequence != hdr_sequence) {
            /* Gap detected, make a note of the details for display in the UI later */
            mcp_analysis_get_frame_data(pinfo->fd->num, TRUE, mcpa);
            mcpa->fd->flags |= MCP_OUT_OF_SEQUENCE;
            mcpa->fd->expected_sequence = mcpa->next_sequence;
        }
        mcpa->next_sequence = hdr_sequence + hdr_count;
    }

    if (!tree) {
        return offset;
    }

    if (hdr_count == 0) {
        /* This must be a heartbeat. */
        if (hdr_length != SEQUENCED_UNIT_HEADER_LEN) {
            /* If count is 0, then the header must be the data. But, this isn't the case here. This
               must be malformed data. */
            return offset;
        }
        
        item = proto_tree_add_protocol_format(
                tree, proto_mcastpitch, tvb,
                0,
                8, "Multicast PITCH Header (Heartbeat)");

        col_set_str(pinfo->cinfo, COL_INFO, "MC PITCH Heartbeat");
    }
    else {
        item = proto_tree_add_protocol_format(
                tree, proto_mcastpitch, tvb,
                0,
                8, "Multicast PITCH Header (%u message%s)",
                hdr_count,
                plurality(hdr_count, "", "s"));

        col_add_fstr(pinfo->cinfo, COL_INFO, "MC PITCH (%u message%s)", hdr_count, plurality(hdr_count, "", "s"));
    }
                
    mcastpitch_tree = proto_item_add_subtree(item, ett_mcastpitch);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCPITCH");
    
    /* header */
    proto_tree_add_item(mcastpitch_tree, hf_mcastpitch_hdr_length,   tvb, 0, 2, TRUE);
    proto_tree_add_item(mcastpitch_tree, hf_mcastpitch_hdr_count,    tvb, 2, 1, TRUE);
    proto_tree_add_item(mcastpitch_tree, hf_mcastpitch_hdr_unit,     tvb, 3, 1, TRUE);
    sequence_item = proto_tree_add_item(mcastpitch_tree, hf_mcastpitch_hdr_sequence, tvb, 4, 4, TRUE);

    /* Check for any "interesting" flags on this frame */
    mcp_analysis_get_frame_data(pinfo->fd->num, FALSE, mcpa);
    if (mcpa && mcpa->fd && mcpa->fd->flags) {
        if (mcpa->fd->flags & MCP_OUT_OF_SEQUENCE) {
            expert_add_info_format(pinfo, sequence_item, &ei_mcastpitch_out_of_sequence,
                "Out-of-sequence, expected: %u, actual: %u", mcpa->fd->expected_sequence, hdr_sequence);
        }
    }  

    /* messages (if any) */
    offset = SEQUENCED_UNIT_HEADER_LEN;
    while (hdr_count--) {
        guint8 msg_length, msg_type, result;

        msg_length = tvb_get_guint8(tvb, offset);
        msg_type   = tvb_get_guint8(tvb, offset + 1);

        if (msg_length > tvb_length_remaining(tvb, offset)) {
            /* Not enough data remaining for the supposed length. This must be malformed data. */
            return offset;
        }

        switch (msg_type) {
            case 0x01:
                result = dissect_login_message(tvb, tree, &offset);
                break;

            case 0x02:
                result = dissect_login_response_message(tvb, tree, &offset);
                break;

            case 0x03:
                result = dissect_gap_request_message(tvb, tree, &offset);
                break;

            case 0x04:
                result = dissect_gap_response_message(tvb, tree, &offset);
                break;
                
            case 0x20:
                result = dissect_time_message(tvb, tree, &offset);
                break;

            case 0x21:
                result = dissect_add_order_long_message(tvb, tree, &offset);
                break;

            case 0x40:
                result = dissect_add_order_long_eu_message(tvb, tree, &offset);
                break;

            case 0x22:
                result = dissect_add_order_short_message(tvb, tree, msg_length, &offset);
                break;

            case 0x23:
                result = dissect_order_executed_message(tvb, tree, msg_length, &offset);
                break;

            case 0x24:
                result = dissect_order_executed_at_price_size_message(tvb, tree, msg_length, &offset);
                break;

            case 0x25:
                result = dissect_reduce_size_long_message(tvb, tree, &offset);
                break;

            case 0x26:
                result = dissect_reduce_size_short_message(tvb, tree, &offset);
                break;

            case 0x27:
                result = dissect_modify_order_long_message(tvb, tree, msg_length, &offset);
                break;

            case 0x28:
                result = dissect_modify_order_short_message(tvb, tree, msg_length, &offset);
                break;

            case 0x29:
                result = dissect_delete_order_message(tvb, tree, &offset);
                break;

            case 0x2A:
                result = dissect_trade_long_message(tvb, tree, &offset);
                break;

            case 0x41:
                result = dissect_trade_long_eu_message(tvb, tree, &offset);
                break;

            case 0x2B:
                result = dissect_trade_short_message(tvb, tree, msg_length, &offset);
                break;

            case 0x2C:
                result = dissect_trade_break_message(tvb, tree, &offset);
                break;

            case 0x2D:
                result = dissect_end_of_session_message(tvb, tree, &offset);
                break;

            case 0x2E:
                result = dissect_symbol_mapping_message(tvb, tree, &offset);
                break;
                
            case 0x2F:
                result = dissect_add_order_expanded_message(tvb, tree, msg_length, &offset);
                break;

            case 0x30:
                result = dissect_trade_expanded_message(tvb, tree, &offset);
                break;

            case 0x31:
                result = dissect_trading_status_message(tvb, tree, &offset);
                break;

            case 0x32:
                result = dissect_trade_report_message(tvb, tree, &offset);
                break;

            case 0x34:
                result = dissect_statistics_message(tvb, tree, &offset);
                break;

            case 0x80:
                result = dissect_spin_image_available_message(tvb, tree, &offset);
                break;

            case 0x81:
                result = dissect_spin_request_message(tvb, tree, &offset);
                break;

            case 0x82:
                result = dissect_spin_response_message(tvb, tree, &offset);
                break;

            case 0x83:
                result = dissect_spin_finished_message(tvb, tree, &offset);
                break;

            case 0x90:
                result = dissect_latency_stat_message(tvb, tree, &offset);
                break;
                
            case 0x95:
                result = dissect_auction_update_message(tvb, tree, &offset);
                break;

            case 0x96:
                result = dissect_auction_summary_message(tvb, tree, &offset);
                break;

            case 0x97:
                result = dissect_unit_clear_message(tvb, tree, &offset);
                break;

            case 0x98:
                result = dissect_retail_price_improvement_message(tvb, tree, &offset);
                break;
        }

        if (result == 0) {
            return offset;
        }
    }

    return offset;
}

void
proto_reg_handoff_mcastpitch(void)
{
    heur_dissector_add("udp", dissect_mcastpitch, proto_mcastpitch);
    heur_dissector_add("tcp", dissect_mcastpitch, proto_mcastpitch);
    mcastpitch_handle = new_create_dissector_handle(dissect_mcastpitch, proto_mcastpitch);
    dissector_add_handle("udp.port", mcastpitch_handle);
    dissector_add_handle("tcp.port", mcastpitch_handle);
}

void
proto_register_mcastpitch(void)
{
    static hf_register_info hf[] = {
        { &hf_mcastpitch_hdr_length,               { "Hdr Length",               "mcastpitch.hdr_length",               FT_UINT16, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_hdr_count,                { "Hdr Count",                "mcastpitch.hdr_count",                FT_UINT8,  BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_hdr_unit,                 { "Hdr Unit",                 "mcastpitch.hdr_unit",                 FT_UINT8,  BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_hdr_sequence,             { "Hdr Sequence",             "mcastpitch.hdr_sequence",             FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_msg_length,               { "Msg Length",               "mcastpitch.msg_length",               FT_UINT8,  BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_msg_type,                 { "Msg Type",                 "mcastpitch.msg_type",                 FT_UINT8,  BASE_HEX,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_time,                     { "Time",                     "mcastpitch.time",                     FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_time_offset,              { "Time Offset",              "mcastpitch.time_offset",              FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_order_id,                 { "Order ID",                 "mcastpitch.order_id",                 FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_side,                     { "Side",                     "mcastpitch.side",                     FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_long_quantity,            { "Quantity (Long)",          "mcastpitch.qty",                      FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_quantity8,                { "Quantity (Long)",          "mcastpitch.qty",                      FT_UINT64, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_symbol6,                  { "Symbol",                   "mcastpitch.symbol",                   FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_long_price,               { "Price (Long)",             "mcastpitch.price",                    FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_short_quantity,           { "Quantity (Short)",         "mcastpitch.qty",                      FT_UINT16, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_short_price,              { "Price (Short)",            "mcastpitch.price",                    FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_executed_shares,          { "Executed Shares",          "mcastpitch.executed_shares",          FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_execution_id,             { "Execution ID",             "mcastpitch.execution_id",             FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_trade_id,                 { "Trade ID",                 "mcastpitch.trade_id",                 FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_remaining_shares,         { "Remaining Shares",         "mcastpitch.remaining_shares",         FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_long_canceled_shares,     { "Canceled Shares (Long)",   "mcastpitch.canceled_shares",          FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_short_canceled_shares,    { "Canceled Shares (Short)",  "mcastpitch.canceled_shares",          FT_UINT16, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_symbol8,                  { "Symbol",                   "mcastpitch.symbol",                   FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_add_flags,                { "Add Flags",                "mcastpitch.add_flags",                FT_UINT8,  BASE_HEX,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_osi_symbol,               { "OSI Symbol",               "mcastpitch.osi_symbol",               FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_session_sub_id,           { "Session Sub ID",           "mcastpitch.session_sub_id",           FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_username,                 { "Username",                 "mcastpitch.username",                 FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_filler,                   { "Filler",                   "mcastpitch.filler",                   FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_password,                 { "Password",                 "mcastpitch.password",                 FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_login_status,             { "Login Status",             "mcastpitch.login_status",             FT_UINT8,  BASE_HEX,     login_response_status,             0x0, NULL, HFILL } },
        { &hf_mcastpitch_options_symbol_condition, { "Options Symbol Condition", "mcastpitch.symbol_condition",         FT_UINT8,  BASE_HEX,     options_symbol_condition,          0x0, NULL, HFILL } },
        { &hf_mcastpitch_trading_status,           { "Trading Status",           "mcastpitch.trading_status",           FT_UINT8,  BASE_DEC,     trading_status,                    0x0, NULL, HFILL } },
        { &hf_mcastpitch_reg_sho_action,           { "Reg SHO Action",           "mcastpitch.reg_sho_action",           FT_UINT8,  BASE_HEX,     reg_sho_action,                    0x0, NULL, HFILL } },
        { &hf_mcastpitch_retail_price_improvement, { "Retail Price Improvement", "mcastpitch.retail_price_improvement", FT_UINT8,  BASE_HEX,     retail_price_improvement,          0x0, NULL, HFILL } },
        { &hf_mcastpitch_reserved1,                { "Reserved 1",               "mcastpitch.reserved1",                FT_UINT8,  BASE_HEX,     NULL,                              0x0, NULL, HFILL } }, 
        { &hf_mcastpitch_reserved2,                { "Reserved 2",               "mcastpitch.reserved2",                FT_UINT8,  BASE_HEX,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_auction_type,             { "Auction Type",             "mcastpitch.auction_type",             FT_UINT8,  BASE_HEX,     auction_type,                      0x0, NULL, HFILL } },
        { &hf_mcastpitch_reference_price,          { "Reference Price",          "mcastpitch.reference_price",          FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_buy_shares,               { "Buy Shares",               "mcastpitch.buy_shares",               FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_sell_shares,              { "Sell Shares",              "mcastpitch.sell_shares",              FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_indicative_price,         { "Indicative Price",         "mcastpitch.indicative_price",         FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_auction_only_price,       { "Auction Only Price",       "mcastpitch.auction_only_price",       FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_gap_response_status,      { "Gap Response Status",      "mcastpitch.gap_response_status",      FT_UINT8,  BASE_HEX,     gap_response_status,               0x0, NULL, HFILL } },
        { &hf_mcastpitch_spin_response_status,     { "Spin Response Status",     "mcastpitch.spin_response_status",     FT_UINT8,  BASE_HEX,     spin_response_status,              0x0, NULL, HFILL } },
        { &hf_mcastpitch_status,                   { "Status",                   "mcastpitch.auction_only_price",       FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_unit,                     { "Unit",                     "mcastpitch.unit",                     FT_UINT8,  BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_count,                    { "Count",                    "mcastpitch.count",                    FT_UINT16, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_measurement_type,         { "Measurement Type",         "mcastpitch.measurement_type",         FT_UINT8,  BASE_HEX,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_begin_time,               { "Begin Time",               "mcastpitch.begin_time",               FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_end_time,                 { "End Time",                 "mcastpitch.end_time",                 FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_sequence,                 { "Sequence",                 "mcastpitch.sequence",                 FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_order_count,              { "Order Count",              "mcastpitch.order_count",              FT_UINT32, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_minimum,                  { "Minimum",                  "mcastpitch.minimum",                  FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_maximum,                  { "Maximum",                  "mcastpitch.maximum",                  FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_average,                  { "Average",                  "mcastpitch.average",                  FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_standard_deviation,       { "Standard Deviation",       "mcastpitch.standard_deviation",       FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_mode,                     { "Mode",                     "mcastpitch.mode",                     FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_99_9_percentile,          { "99.9 Percentile",          "mcastpitch.99_9_percentile",          FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_99_percentile,            { "99 Percentile",            "mcastpitch.99_percentile",            FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_95_percentile,            { "95 Percentile",            "mcastpitch.95_percentile",            FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_90_percentile,            { "90 Percentile",            "mcastpitch.90_percentile",            FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_75_percentile,            { "75 Percentile",            "mcastpitch.75_percentile",            FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_50_percentile,            { "50 Percentile (Median)",   "mcastpitch.50_percentile",            FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_25_percentile,            { "25 Percentile",            "mcastpitch.25_percentile",            FT_DOUBLE, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_trade_time,               { "Trade Time",               "mcastpitch.trade_time",               FT_UINT64, BASE_DEC,     NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_exec_venue,               { "Execution Venue",          "mcastpitch.exec_venue",               FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_traded_currency,          { "Traded Currency",          "mcastpitch.traded_currency",          FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_trade_report_flags,       { "Trade Report Flags",       "mcastpitch.trade_report_flags",       FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_participant_id,           { "Participant ID",           "mcastpitch.participant_id",           FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_trade_flags,              { "Trade Flags",              "mcastpitch.trade_flags",              FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_execution_flags,          { "Execution Flags",          "mcastpitch.execution_flags",          FT_STRING, BASE_NONE,    NULL,                              0x0, NULL, HFILL } },
        { &hf_mcastpitch_statistic_type,           { "Statistic Type",           "mcastpitch.statistic_type",           FT_UINT8,  BASE_DEC,     statistic_type,                    0x0, NULL, HFILL } },
        { &hf_mcastpitch_price_determination,      { "Price Determination",      "mcastpitch.price_determination",      FT_UINT8,  BASE_DEC,     price_determination,               0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_mcastpitch
    };

    static ei_register_info ei[] = {
        { &ei_mcastpitch_out_of_sequence, { "mcastpitch.out_of_sequence", PI_SEQUENCE, PI_WARN, "Out-of-sequence", EXPFILL }},
    };
        
    expert_module_t *expert_mcastpitch;
        
    proto_mcastpitch = proto_register_protocol(
            "Multicast PITCH",      /* name */
            "BATS Multicast PITCH", /* short name */
            "mcastpitch");          /* abbrev */

    new_register_dissector("mcastpitch", dissect_mcastpitch, proto_mcastpitch);

    proto_register_field_array(proto_mcastpitch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    prefs_register_protocol(proto_mcastpitch, NULL);
    expert_mcastpitch = expert_register_protocol(proto_mcastpitch);
    expert_register_field_array(expert_mcastpitch, ei, array_length(ei));

    add_ip_name_from_string("239.39.62.190", "mcpitch.development");

    /* Populate Wireshark's name lookup hash with names for each Multicast PITCH well-known multicast address. */

    /* Format:
       mcpitch
       <data center>        nj2, ny5, ch4
       <low matching unit>  (u1)
       <high matching unit> (u4)
       <feed type>          rt = realtime, gap = gap response
       <market + shape>     za => (z = BZX, a = GIG A)
    */

    /* --------------------------------------------------------------------------------
     * BZX Market
     * -------------------------------------------------------------------------------- */
    
    /* NJ2 - BZX - GIG A - Realtime */
    add_ip_name_from_string("224.0.62.2",  "mcpitch.nj2.u1.u4.rt.za");
    add_ip_name_from_string("224.0.62.4",  "mcpitch.nj2.u5.u8.rt.za");
    add_ip_name_from_string("224.0.62.6",  "mcpitch.nj2.u9.u12.rt.za");
    add_ip_name_from_string("224.0.62.8",  "mcpitch.nj2.u13.u16.rt.za");
    add_ip_name_from_string("224.0.62.10", "mcpitch.nj2.u17.u20.rt.za");
    add_ip_name_from_string("224.0.62.12", "mcpitch.nj2.u21.u24.rt.za");
    add_ip_name_from_string("224.0.62.30", "mcpitch.nj2.u25.u28.rt.za");
    add_ip_name_from_string("224.0.62.32", "mcpitch.nj2.u29.u32.rt.za");

    /* NJ2 - BZX - GIG A - Gap */
    add_ip_name_from_string("224.0.62.3",  "mcpitch.nj2.u1.u4.gap.za");
    add_ip_name_from_string("224.0.62.5",  "mcpitch.nj2.u5.u8.gap.za");
    add_ip_name_from_string("224.0.62.7",  "mcpitch.nj2.u9.u12.gap.za");
    add_ip_name_from_string("224.0.62.9",  "mcpitch.nj2.u13.u16.gap.za");
    add_ip_name_from_string("224.0.62.11", "mcpitch.nj2.u17.u20.gap.za");
    add_ip_name_from_string("224.0.62.13", "mcpitch.nj2.u21.u24.gap.za");
    add_ip_name_from_string("224.0.62.31", "mcpitch.nj2.u25.u28.gap.za");
    add_ip_name_from_string("224.0.62.33", "mcpitch.nj2.u29.u32.gap.za");

    /* NJ2 - BZX - WAN C - Realtime */
    add_ip_name_from_string("224.0.62.14", "mcpitch.nj2.u1.u4.rt.zc");
    add_ip_name_from_string("224.0.62.16", "mcpitch.nj2.u5.u8.rt.zc");
    add_ip_name_from_string("224.0.62.18", "mcpitch.nj2.u9.u12.rt.zc");
    add_ip_name_from_string("224.0.62.20", "mcpitch.nj2.u13.u16.rt.zc");
    add_ip_name_from_string("224.0.62.22", "mcpitch.nj2.u17.u20.rt.zc");
    add_ip_name_from_string("224.0.62.24", "mcpitch.nj2.u21.u24.rt.zc");
    add_ip_name_from_string("224.0.62.26", "mcpitch.nj2.u25.u28.rt.zc");
    add_ip_name_from_string("224.0.62.28", "mcpitch.nj2.u29.u32.rt.zc");

    /* NJ2 - BZX - WAN C - Gap */
    add_ip_name_from_string("224.0.62.15", "mcpitch.nj2.u1.u4.gap.zc");
    add_ip_name_from_string("224.0.62.17", "mcpitch.nj2.u5.u8.gap.zc");
    add_ip_name_from_string("224.0.62.19", "mcpitch.nj2.u9.u12.gap.zc");
    add_ip_name_from_string("224.0.62.21", "mcpitch.nj2.u13.u16.gap.zc");
    add_ip_name_from_string("224.0.62.23", "mcpitch.nj2.u17.u20.gap.zc");
    add_ip_name_from_string("224.0.62.25", "mcpitch.nj2.u21.u24.gap.zc");
    add_ip_name_from_string("224.0.62.27", "mcpitch.nj2.u25.u28.gap.zc");
    add_ip_name_from_string("224.0.62.29", "mcpitch.nj2.u29.u32.gap.zc");

    /* NJ2 - BZX - GIG B - Realtime */
    add_ip_name_from_string("233.19.3.128", "mcpitch.nj2.u1.u4.rt.zb");
    add_ip_name_from_string("233.19.3.130", "mcpitch.nj2.u5.u8.rt.zb");
    add_ip_name_from_string("233.19.3.132", "mcpitch.nj2.u9.u12.rt.zb");
    add_ip_name_from_string("233.19.3.134", "mcpitch.nj2.u13.u16.rt.zb");
    add_ip_name_from_string("233.19.3.136", "mcpitch.nj2.u17.u20.rt.zb");
    add_ip_name_from_string("233.19.3.138", "mcpitch.nj2.u21.u24.rt.zb");
    add_ip_name_from_string("233.19.3.140", "mcpitch.nj2.u25.u28.rt.zb");
    add_ip_name_from_string("233.19.3.142", "mcpitch.nj2.u29.u32.rt.zb");

    /* NJ2 - BZX - GIG B - Gap */
    add_ip_name_from_string("233.19.3.129", "mcpitch.nj2.u1.u4.gap.zb");
    add_ip_name_from_string("233.19.3.131", "mcpitch.nj2.u5.u8.gap.zb");
    add_ip_name_from_string("233.19.3.133", "mcpitch.nj2.u9.u12.gap.zb");
    add_ip_name_from_string("233.19.3.135", "mcpitch.nj2.u13.u16.gap.zb");
    add_ip_name_from_string("233.19.3.137", "mcpitch.nj2.u17.u20.gap.zb");
    add_ip_name_from_string("233.19.3.139", "mcpitch.nj2.u21.u24.gap.zb");
    add_ip_name_from_string("233.19.3.141", "mcpitch.nj2.u25.u28.gap.zb");
    add_ip_name_from_string("233.19.3.143", "mcpitch.nj2.u29.u32.gap.zb");

    /* NJ2 - BZX - WAN D - Realtime */
    add_ip_name_from_string("233.19.3.144", "mcpitch.nj2.u1.u4.rt.zd");
    add_ip_name_from_string("233.19.3.146", "mcpitch.nj2.u5.u8.rt.zd");
    add_ip_name_from_string("233.19.3.148", "mcpitch.nj2.u9.u12.rt.zd");
    add_ip_name_from_string("233.19.3.150", "mcpitch.nj2.u13.u16.rt.zd");
    add_ip_name_from_string("233.19.3.152", "mcpitch.nj2.u17.u20.rt.zd");
    add_ip_name_from_string("233.19.3.154", "mcpitch.nj2.u21.u24.rt.zd");
    add_ip_name_from_string("233.19.3.156", "mcpitch.nj2.u25.u28.rt.zd");
    add_ip_name_from_string("233.19.3.158", "mcpitch.nj2.u29.u32.rt.zd");

    /* NJ2 - BZX - WAN D - Gap */
    add_ip_name_from_string("233.19.3.145", "mcpitch.nj2.u1.u4.gap.zd");
    add_ip_name_from_string("233.19.3.147", "mcpitch.nj2.u5.u8.gap.zd");
    add_ip_name_from_string("233.19.3.149", "mcpitch.nj2.u9.u12.gap.zd");
    add_ip_name_from_string("233.19.3.151", "mcpitch.nj2.u13.u16.gap.zd");
    add_ip_name_from_string("233.19.3.153", "mcpitch.nj2.u17.u20.gap.zd");
    add_ip_name_from_string("233.19.3.155", "mcpitch.nj2.u21.u24.gap.zd");
    add_ip_name_from_string("233.19.3.157", "mcpitch.nj2.u25.u28.gap.zd");
    add_ip_name_from_string("233.19.3.159", "mcpitch.nj2.u29.u32.gap.zd");

    /* NY5 - BZX - GIG A - Realtime */
    add_ip_name_from_string("224.0.130.128", "mcpitch.ny5.u1.u4.rt.za");
    add_ip_name_from_string("224.0.130.129", "mcpitch.ny5.u5.u8.rt.za");
    add_ip_name_from_string("224.0.130.130", "mcpitch.ny5.u9.u12.rt.za");
    add_ip_name_from_string("224.0.130.131", "mcpitch.ny5.u13.u16.rt.za");
    add_ip_name_from_string("224.0.130.132", "mcpitch.ny5.u17.u20.rt.za");
    add_ip_name_from_string("224.0.130.133", "mcpitch.ny5.u21.u24.rt.za");
    add_ip_name_from_string("224.0.130.134", "mcpitch.ny5.u25.u28.rt.za");
    add_ip_name_from_string("224.0.130.135", "mcpitch.ny5.u29.u32.rt.za");

    /* NY5 - BZX - GIG A - Gap */
    add_ip_name_from_string("224.0.130.144", "mcpitch.ny5.u1.u4.gap.za");
    add_ip_name_from_string("224.0.130.145", "mcpitch.ny5.u5.u8.gap.za");
    add_ip_name_from_string("224.0.130.146", "mcpitch.ny5.u9.u12.gap.za");
    add_ip_name_from_string("224.0.130.147", "mcpitch.ny5.u13.u16.gap.za");
    add_ip_name_from_string("224.0.130.148", "mcpitch.ny5.u17.u20.gap.za");
    add_ip_name_from_string("224.0.130.149", "mcpitch.ny5.u21.u24.gap.za");
    add_ip_name_from_string("224.0.130.150", "mcpitch.ny5.u25.u28.gap.za");
    add_ip_name_from_string("224.0.130.151", "mcpitch.ny5.u29.u32.gap.za");

    /* NY5 - BZX - WAN C - Realtime */
    add_ip_name_from_string("224.0.130.160", "mcpitch.ny5.u1.u4.rt.zc");
    add_ip_name_from_string("224.0.130.161", "mcpitch.ny5.u5.u8.rt.zc");
    add_ip_name_from_string("224.0.130.162", "mcpitch.ny5.u9.u12.rt.zc");
    add_ip_name_from_string("224.0.130.163", "mcpitch.ny5.u13.u16.rt.zc");
    add_ip_name_from_string("224.0.130.164", "mcpitch.ny5.u17.u20.rt.zc");
    add_ip_name_from_string("224.0.130.165", "mcpitch.ny5.u21.u24.rt.zc");
    add_ip_name_from_string("224.0.130.166", "mcpitch.ny5.u25.u28.rt.zc");
    add_ip_name_from_string("224.0.130.167", "mcpitch.ny5.u29.u32.rt.zc");

    /* NY5 - BZX - WAN C - Gap */
    add_ip_name_from_string("224.0.130.176", "mcpitch.ny5.u1.u4.gap.zc");
    add_ip_name_from_string("224.0.130.177", "mcpitch.ny5.u5.u8.gap.zc");
    add_ip_name_from_string("224.0.130.178", "mcpitch.ny5.u9.u12.gap.zc");
    add_ip_name_from_string("224.0.130.179", "mcpitch.ny5.u13.u16.gap.zc");
    add_ip_name_from_string("224.0.130.180", "mcpitch.ny5.u17.u20.gap.zc");
    add_ip_name_from_string("224.0.130.181", "mcpitch.ny5.u21.u24.gap.zc");
    add_ip_name_from_string("224.0.130.182", "mcpitch.ny5.u25.u28.gap.zc");
    add_ip_name_from_string("224.0.130.183", "mcpitch.ny5.u29.u32.gap.zc");

    /* NY5 - BZX - GIG B - Realtime */
    add_ip_name_from_string("233.209.92.128", "mcpitch.ny5.u1.u4.rt.zb");
    add_ip_name_from_string("233.209.92.129", "mcpitch.ny5.u5.u8.rt.zb");
    add_ip_name_from_string("233.209.92.130", "mcpitch.ny5.u9.u12.rt.zb");
    add_ip_name_from_string("233.209.92.131", "mcpitch.ny5.u13.u16.rt.zb");
    add_ip_name_from_string("233.209.92.132", "mcpitch.ny5.u17.u20.rt.zb");
    add_ip_name_from_string("233.209.92.133", "mcpitch.ny5.u21.u24.rt.zb");
    add_ip_name_from_string("233.209.92.134", "mcpitch.ny5.u25.u28.rt.zb");
    add_ip_name_from_string("233.209.92.135", "mcpitch.ny5.u29.u32.rt.zb");

    /* NY5 - BZX - GIG B - Gap */
    add_ip_name_from_string("233.209.92.144", "mcpitch.ny5.u1.u4.gap.zb");
    add_ip_name_from_string("233.209.92.145", "mcpitch.ny5.u5.u8.gap.zb");
    add_ip_name_from_string("233.209.92.146", "mcpitch.ny5.u9.u12.gap.zb");
    add_ip_name_from_string("233.209.92.147", "mcpitch.ny5.u13.u16.gap.zb");
    add_ip_name_from_string("233.209.92.148", "mcpitch.ny5.u17.u20.gap.zb");
    add_ip_name_from_string("233.209.92.149", "mcpitch.ny5.u21.u24.gap.zb");
    add_ip_name_from_string("233.209.92.150", "mcpitch.ny5.u25.u28.gap.zb");
    add_ip_name_from_string("233.209.92.151", "mcpitch.ny5.u29.u32.gap.zb");

    /* NY5 - BZX - WAN D - Realtime */
    add_ip_name_from_string("233.209.92.160", "mcpitch.ny5.u1.u4.rt.zd");
    add_ip_name_from_string("233.209.92.161", "mcpitch.ny5.u5.u8.rt.zd");
    add_ip_name_from_string("233.209.92.162", "mcpitch.ny5.u9.u12.rt.zd");
    add_ip_name_from_string("233.209.92.163", "mcpitch.ny5.u13.u16.rt.zd");
    add_ip_name_from_string("233.209.92.164", "mcpitch.ny5.u17.u20.rt.zd");
    add_ip_name_from_string("233.209.92.165", "mcpitch.ny5.u21.u24.rt.zd");
    add_ip_name_from_string("233.209.92.166", "mcpitch.ny5.u25.u28.rt.zd");
    add_ip_name_from_string("233.209.92.167", "mcpitch.ny5.u29.u32.rt.zd");

    /* NY5 - BZX - WAN D - Gap */
    add_ip_name_from_string("233.209.92.176", "mcpitch.ny5.u1.u4.gap.zd");
    add_ip_name_from_string("233.209.92.177", "mcpitch.ny5.u5.u8.gap.zd");
    add_ip_name_from_string("233.209.92.178", "mcpitch.ny5.u9.u12.gap.zd");
    add_ip_name_from_string("233.209.92.179", "mcpitch.ny5.u13.u16.gap.zd");
    add_ip_name_from_string("233.209.92.180", "mcpitch.ny5.u17.u20.gap.zd");
    add_ip_name_from_string("233.209.92.181", "mcpitch.ny5.u21.u24.gap.zd");
    add_ip_name_from_string("233.209.92.182", "mcpitch.ny5.u25.u28.gap.zd");
    add_ip_name_from_string("233.209.92.183", "mcpitch.ny5.u29.u32.gap.zd");

    /* CH4 - BZX - WAN E - Realtime */
    add_ip_name_from_string("233.19.3.80", "mcpitch.ch4.u1.u4.rt.ze");
    add_ip_name_from_string("233.19.3.82", "mcpitch.ch4.u5.u8.rt.ze");
    add_ip_name_from_string("233.19.3.84", "mcpitch.ch4.u9.u12.rt.ze");
    add_ip_name_from_string("233.19.3.86", "mcpitch.ch4.u13.u16.rt.ze");
    add_ip_name_from_string("233.19.3.88", "mcpitch.ch4.u17.u20.rt.ze");
    add_ip_name_from_string("233.19.3.90", "mcpitch.ch4.u21.u24.rt.ze");
    add_ip_name_from_string("233.19.3.92", "mcpitch.ch4.u25.u28.rt.ze");
    add_ip_name_from_string("233.19.3.94", "mcpitch.ch4.u29.u32.rt.ze");

    /* CH4 - BZX - WAN E - Gap */
    add_ip_name_from_string("233.19.3.81", "mcpitch.ny5.u1.u4.gap.ze");
    add_ip_name_from_string("233.19.3.83", "mcpitch.ny5.u5.u8.gap.ze");
    add_ip_name_from_string("233.19.3.85", "mcpitch.ny5.u9.u12.gap.ze");
    add_ip_name_from_string("233.19.3.87", "mcpitch.ny5.u13.u16.gap.ze");
    add_ip_name_from_string("233.19.3.89", "mcpitch.ny5.u17.u20.gap.ze");
    add_ip_name_from_string("233.19.3.91", "mcpitch.ny5.u21.u24.gap.ze");
    add_ip_name_from_string("233.19.3.93", "mcpitch.ny5.u25.u28.gap.ze");
    add_ip_name_from_string("233.19.3.95", "mcpitch.ny5.u29.u32.gap.ze");

    /* --------------------------------------------------------------------------------
     * BYX Market
     * -------------------------------------------------------------------------------- */

    /* NJ2 - BYX - GIG A - Realtime */
    add_ip_name_from_string("224.0.62.192", "mcpitch.nj2.u1.u4.rt.ya");
    add_ip_name_from_string("224.0.62.194", "mcpitch.nj2.u5.u8.rt.ya");
    add_ip_name_from_string("224.0.62.196", "mcpitch.nj2.u9.u12.rt.ya");
    add_ip_name_from_string("224.0.62.198", "mcpitch.nj2.u13.u16.rt.ya");
    add_ip_name_from_string("224.0.62.200", "mcpitch.nj2.u17.u20.rt.ya");
    add_ip_name_from_string("224.0.62.202", "mcpitch.nj2.u21.u24.rt.ya");
    add_ip_name_from_string("224.0.62.204", "mcpitch.nj2.u25.u28.rt.ya");
    add_ip_name_from_string("224.0.62.206", "mcpitch.nj2.u29.u32.rt.ya");

    /* NJ2 - BYX - GIG A - Gap */
    add_ip_name_from_string("224.0.62.193", "mcpitch.nj2.u1.u4.gap.ya");
    add_ip_name_from_string("224.0.62.195", "mcpitch.nj2.u5.u8.gap.ya");
    add_ip_name_from_string("224.0.62.197", "mcpitch.nj2.u9.u12.gap.ya");
    add_ip_name_from_string("224.0.62.199", "mcpitch.nj2.u13.u16.gap.ya");
    add_ip_name_from_string("224.0.62.201", "mcpitch.nj2.u17.u20.gap.ya");
    add_ip_name_from_string("224.0.62.203", "mcpitch.nj2.u21.u24.gap.ya");
    add_ip_name_from_string("224.0.62.205", "mcpitch.nj2.u25.u28.gap.ya");
    add_ip_name_from_string("224.0.62.207", "mcpitch.nj2.u29.u32.gap.ya");

    /* NJ2 - BYX - WAN C - Realtime */
    add_ip_name_from_string("224.0.62.208", "mcpitch.nj2.u1.u4.rt.yc");
    add_ip_name_from_string("224.0.62.210", "mcpitch.nj2.u5.u8.rt.yc");
    add_ip_name_from_string("224.0.62.212", "mcpitch.nj2.u9.u12.rt.yc");
    add_ip_name_from_string("224.0.62.214", "mcpitch.nj2.u13.u16.rt.yc");
    add_ip_name_from_string("224.0.62.216", "mcpitch.nj2.u17.u20.rt.yc");
    add_ip_name_from_string("224.0.62.218", "mcpitch.nj2.u21.u24.rt.yc");
    add_ip_name_from_string("224.0.62.220", "mcpitch.nj2.u25.u28.rt.yc");
    add_ip_name_from_string("224.0.62.222", "mcpitch.nj2.u29.u32.rt.yc");

    /* NJ2 - BYX - WAN C - Gap */
    add_ip_name_from_string("224.0.62.209", "mcpitch.nj2.u1.u4.gap.yc");
    add_ip_name_from_string("224.0.62.211", "mcpitch.nj2.u5.u8.gap.yc");
    add_ip_name_from_string("224.0.62.213", "mcpitch.nj2.u9.u12.gap.yc");
    add_ip_name_from_string("224.0.62.215", "mcpitch.nj2.u13.u16.gap.yc");
    add_ip_name_from_string("224.0.62.217", "mcpitch.nj2.u17.u20.gap.yc");
    add_ip_name_from_string("224.0.62.219", "mcpitch.nj2.u21.u24.gap.yc");
    add_ip_name_from_string("224.0.62.221", "mcpitch.nj2.u25.u28.gap.yc");
    add_ip_name_from_string("224.0.62.223", "mcpitch.nj2.u29.u32.gap.yc");

    /* NJ2 - BYX - GIG B - Realtime */
    add_ip_name_from_string("233.19.3.192", "mcpitch.nj2.u1.u4.rt.yb");
    add_ip_name_from_string("233.19.3.194", "mcpitch.nj2.u5.u8.rt.yb");
    add_ip_name_from_string("233.19.3.196", "mcpitch.nj2.u9.u12.rt.yb");
    add_ip_name_from_string("233.19.3.198", "mcpitch.nj2.u13.u16.rt.yb");
    add_ip_name_from_string("233.19.3.200", "mcpitch.nj2.u17.u20.rt.yb");
    add_ip_name_from_string("233.19.3.202", "mcpitch.nj2.u21.u24.rt.yb");
    add_ip_name_from_string("233.19.3.204", "mcpitch.nj2.u25.u28.rt.yb");
    add_ip_name_from_string("233.19.3.206", "mcpitch.nj2.u29.u32.rt.yb");

    /* NJ2 - BYX - GIG B - Gap */
    add_ip_name_from_string("233.19.3.193", "mcpitch.nj2.u1.u4.gap.yb");
    add_ip_name_from_string("233.19.3.195", "mcpitch.nj2.u5.u8.gap.yb");
    add_ip_name_from_string("233.19.3.197", "mcpitch.nj2.u9.u12.gap.yb");
    add_ip_name_from_string("233.19.3.199", "mcpitch.nj2.u13.u16.gap.yb");
    add_ip_name_from_string("233.19.3.201", "mcpitch.nj2.u17.u20.gap.yb");
    add_ip_name_from_string("233.19.3.203", "mcpitch.nj2.u21.u24.gap.yb");
    add_ip_name_from_string("233.19.3.205", "mcpitch.nj2.u25.u28.gap.yb");
    add_ip_name_from_string("233.19.3.207", "mcpitch.nj2.u29.u32.gap.yb");

    /* NJ2 - BYX - WAN D - Realtime */
    add_ip_name_from_string("233.19.3.208", "mcpitch.nj2.u1.u4.rt.yd");
    add_ip_name_from_string("233.19.3.210", "mcpitch.nj2.u5.u8.rt.yd");
    add_ip_name_from_string("233.19.3.212", "mcpitch.nj2.u9.u12.rt.yd");
    add_ip_name_from_string("233.19.3.214", "mcpitch.nj2.u13.u16.rt.yd");
    add_ip_name_from_string("233.19.3.216", "mcpitch.nj2.u17.u20.rt.yd");
    add_ip_name_from_string("233.19.3.218", "mcpitch.nj2.u21.u24.rt.yd");
    add_ip_name_from_string("233.19.3.220", "mcpitch.nj2.u25.u28.rt.yd");
    add_ip_name_from_string("233.19.3.222", "mcpitch.nj2.u29.u32.rt.yd");

    /* NJ2 - BYX - WAN D - Gap */
    add_ip_name_from_string("233.19.3.209", "mcpitch.nj2.u1.u4.gap.yd");
    add_ip_name_from_string("233.19.3.211", "mcpitch.nj2.u5.u8.gap.yd");
    add_ip_name_from_string("233.19.3.213", "mcpitch.nj2.u9.u12.gap.yd");
    add_ip_name_from_string("233.19.3.215", "mcpitch.nj2.u13.u16.gap.yd");
    add_ip_name_from_string("233.19.3.217", "mcpitch.nj2.u17.u20.gap.yd");
    add_ip_name_from_string("233.19.3.219", "mcpitch.nj2.u21.u24.gap.yd");
    add_ip_name_from_string("233.19.3.221", "mcpitch.nj2.u25.u28.gap.yd");
    add_ip_name_from_string("233.19.3.223", "mcpitch.nj2.u29.u32.gap.yd");

    /* NY5 - BYX - GIG A - Realtime */
    add_ip_name_from_string("224.0.130.192", "mcpitch.ny5.u1.u4.rt.ya");
    add_ip_name_from_string("224.0.130.193", "mcpitch.ny5.u5.u8.rt.ya");
    add_ip_name_from_string("224.0.130.194", "mcpitch.ny5.u9.u12.rt.ya");
    add_ip_name_from_string("224.0.130.195", "mcpitch.ny5.u13.u16.rt.ya");
    add_ip_name_from_string("224.0.130.196", "mcpitch.ny5.u17.u20.rt.ya");
    add_ip_name_from_string("224.0.130.197", "mcpitch.ny5.u21.u24.rt.ya");
    add_ip_name_from_string("224.0.130.198", "mcpitch.ny5.u25.u28.rt.ya");
    add_ip_name_from_string("224.0.130.199", "mcpitch.ny5.u29.u32.rt.ya");

    /* NY5 - BYX - GIG A - Gap */
    add_ip_name_from_string("224.0.130.208", "mcpitch.ny5.u1.u4.gap.ya");
    add_ip_name_from_string("224.0.130.209", "mcpitch.ny5.u5.u8.gap.ya");
    add_ip_name_from_string("224.0.130.210", "mcpitch.ny5.u9.u12.gap.ya");
    add_ip_name_from_string("224.0.130.211", "mcpitch.ny5.u13.u16.gap.ya");
    add_ip_name_from_string("224.0.130.212", "mcpitch.ny5.u17.u20.gap.ya");
    add_ip_name_from_string("224.0.130.213", "mcpitch.ny5.u21.u24.gap.ya");
    add_ip_name_from_string("224.0.130.214", "mcpitch.ny5.u25.u28.gap.ya");
    add_ip_name_from_string("224.0.130.215", "mcpitch.ny5.u29.u32.gap.ya");

    /* NY5 - BYX - WAN C - Realtime */
    add_ip_name_from_string("224.0.130.224", "mcpitch.ny5.u1.u4.rt.yc");
    add_ip_name_from_string("224.0.130.225", "mcpitch.ny5.u5.u8.rt.yc");
    add_ip_name_from_string("224.0.130.226", "mcpitch.ny5.u9.u12.rt.yc");
    add_ip_name_from_string("224.0.130.227", "mcpitch.ny5.u13.u16.rt.yc");
    add_ip_name_from_string("224.0.130.228", "mcpitch.ny5.u17.u20.rt.yc");
    add_ip_name_from_string("224.0.130.229", "mcpitch.ny5.u21.u24.rt.yc");
    add_ip_name_from_string("224.0.130.230", "mcpitch.ny5.u25.u28.rt.yc");
    add_ip_name_from_string("224.0.130.231", "mcpitch.ny5.u29.u32.rt.yc");

    /* NY5 - BYX - WAN C - Gap */
    add_ip_name_from_string("224.0.130.240", "mcpitch.ny5.u1.u4.gap.yc");
    add_ip_name_from_string("224.0.130.241", "mcpitch.ny5.u5.u8.gap.yc");
    add_ip_name_from_string("224.0.130.242", "mcpitch.ny5.u9.u12.gap.yc");
    add_ip_name_from_string("224.0.130.243", "mcpitch.ny5.u13.u16.gap.yc");
    add_ip_name_from_string("224.0.130.244", "mcpitch.ny5.u17.u20.gap.yc");
    add_ip_name_from_string("224.0.130.245", "mcpitch.ny5.u21.u24.gap.yc");
    add_ip_name_from_string("224.0.130.246", "mcpitch.ny5.u25.u28.gap.yc");
    add_ip_name_from_string("224.0.130.247", "mcpitch.ny5.u29.u32.gap.yc");

    /* NY5 - BYX - GIG B - Realtime */
    add_ip_name_from_string("233.209.92.192", "mcpitch.ny5.u1.u4.rt.yb");
    add_ip_name_from_string("233.209.92.193", "mcpitch.ny5.u5.u8.rt.yb");
    add_ip_name_from_string("233.209.92.194", "mcpitch.ny5.u9.u12.rt.yb");
    add_ip_name_from_string("233.209.92.195", "mcpitch.ny5.u13.u16.rt.yb");
    add_ip_name_from_string("233.209.92.196", "mcpitch.ny5.u17.u20.rt.yb");
    add_ip_name_from_string("233.209.92.197", "mcpitch.ny5.u21.u24.rt.yb");
    add_ip_name_from_string("233.209.92.198", "mcpitch.ny5.u25.u28.rt.yb");
    add_ip_name_from_string("233.209.92.199", "mcpitch.ny5.u29.u32.rt.yb");

    /* NY5 - BYX - GIG B - Gap */
    add_ip_name_from_string("233.209.92.208", "mcpitch.ny5.u1.u4.gap.yb");
    add_ip_name_from_string("233.209.92.209", "mcpitch.ny5.u5.u8.gap.yb");
    add_ip_name_from_string("233.209.92.210", "mcpitch.ny5.u9.u12.gap.yb");
    add_ip_name_from_string("233.209.92.211", "mcpitch.ny5.u13.u16.gap.yb");
    add_ip_name_from_string("233.209.92.212", "mcpitch.ny5.u17.u20.gap.yb");
    add_ip_name_from_string("233.209.92.213", "mcpitch.ny5.u21.u24.gap.yb");
    add_ip_name_from_string("233.209.92.214", "mcpitch.ny5.u25.u28.gap.yb");
    add_ip_name_from_string("233.209.92.215", "mcpitch.ny5.u29.u32.gap.yb");

    /* NY5 - BYX - WAN D - Realtime */
    add_ip_name_from_string("233.209.92.224", "mcpitch.ny5.u1.u4.rt.yd");
    add_ip_name_from_string("233.209.92.225", "mcpitch.ny5.u5.u8.rt.yd");
    add_ip_name_from_string("233.209.92.226", "mcpitch.ny5.u9.u12.rt.yd");
    add_ip_name_from_string("233.209.92.227", "mcpitch.ny5.u13.u16.rt.yd");
    add_ip_name_from_string("233.209.92.228", "mcpitch.ny5.u17.u20.rt.yd");
    add_ip_name_from_string("233.209.92.229", "mcpitch.ny5.u21.u24.rt.yd");
    add_ip_name_from_string("233.209.92.230", "mcpitch.ny5.u25.u28.rt.yd");
    add_ip_name_from_string("233.209.92.231", "mcpitch.ny5.u29.u32.rt.yd");

    /* NY5 - BYX - WAN D - Gap */
    add_ip_name_from_string("233.209.92.240", "mcpitch.ny5.u1.u4.gap.yd");
    add_ip_name_from_string("233.209.92.241", "mcpitch.ny5.u5.u8.gap.yd");
    add_ip_name_from_string("233.209.92.242", "mcpitch.ny5.u9.u12.gap.yd");
    add_ip_name_from_string("233.209.92.243", "mcpitch.ny5.u13.u16.gap.yd");
    add_ip_name_from_string("233.209.92.244", "mcpitch.ny5.u17.u20.gap.yd");
    add_ip_name_from_string("233.209.92.245", "mcpitch.ny5.u21.u24.gap.yd");
    add_ip_name_from_string("233.209.92.246", "mcpitch.ny5.u25.u28.gap.yd");
    add_ip_name_from_string("233.209.92.247", "mcpitch.ny5.u29.u32.gap.yd");

    /* CH4 - BYX - WAN E - Realtime */
    add_ip_name_from_string("233.19.3.112", "mcpitch.ch4.u1.u4.rt.ye");
    add_ip_name_from_string("233.19.3.114", "mcpitch.ch4.u5.u8.rt.ye");
    add_ip_name_from_string("233.19.3.116", "mcpitch.ch4.u9.u12.rt.ye");
    add_ip_name_from_string("233.19.3.118", "mcpitch.ch4.u13.u16.rt.ye");
    add_ip_name_from_string("233.19.3.120", "mcpitch.ch4.u17.u20.rt.ye");
    add_ip_name_from_string("233.19.3.122", "mcpitch.ch4.u21.u24.rt.ye");
    add_ip_name_from_string("233.19.3.124", "mcpitch.ch4.u25.u28.rt.ye");
    add_ip_name_from_string("233.19.3.126", "mcpitch.ch4.u29.u32.rt.ye");

    /* CH4 - BYX - WAN E - Gap */
    add_ip_name_from_string("233.19.3.113", "mcpitch.ny5.u1.u4.gap.ye");
    add_ip_name_from_string("233.19.3.115", "mcpitch.ny5.u5.u8.gap.ye");
    add_ip_name_from_string("233.19.3.117", "mcpitch.ny5.u9.u12.gap.ye");
    add_ip_name_from_string("233.19.3.119", "mcpitch.ny5.u13.u16.gap.ye");
    add_ip_name_from_string("233.19.3.121", "mcpitch.ny5.u17.u20.gap.ye");
    add_ip_name_from_string("233.19.3.123", "mcpitch.ny5.u21.u24.gap.ye");
    add_ip_name_from_string("233.19.3.125", "mcpitch.ny5.u25.u28.gap.ye");
    add_ip_name_from_string("233.19.3.127", "mcpitch.ny5.u29.u32.gap.ye");

    /* --------------------------------------------------------------------------------
     * EDGA Market
     * -------------------------------------------------------------------------------- */
    
    /* NY5 - EDGA - GIG A - Realtime */
    add_ip_name_from_string("224.0.130.0", "mcpitch.ny5.u1.u4.rt.aa");
    add_ip_name_from_string("224.0.130.1", "mcpitch.ny5.u5.u8.rt.aa");
    add_ip_name_from_string("224.0.130.2", "mcpitch.ny5.u9.u12.rt.aa");
    add_ip_name_from_string("224.0.130.3", "mcpitch.ny5.u13.u16.rt.aa");
    add_ip_name_from_string("224.0.130.4", "mcpitch.ny5.u17.u20.rt.aa");
    add_ip_name_from_string("224.0.130.5", "mcpitch.ny5.u21.u24.rt.aa");
    add_ip_name_from_string("224.0.130.6", "mcpitch.ny5.u25.u28.rt.aa");
    add_ip_name_from_string("224.0.130.7", "mcpitch.ny5.u29.u32.rt.aa");

    /* NY5 - EDGA - GIG A - Gap */
    add_ip_name_from_string("224.0.130.16", "mcpitch.ny5.u1.u4.gap.aa");
    add_ip_name_from_string("224.0.130.17", "mcpitch.ny5.u5.u8.gap.aa");
    add_ip_name_from_string("224.0.130.18", "mcpitch.ny5.u9.u12.gap.aa");
    add_ip_name_from_string("224.0.130.19", "mcpitch.ny5.u13.u16.gap.aa");
    add_ip_name_from_string("224.0.130.20", "mcpitch.ny5.u17.u20.gap.aa");
    add_ip_name_from_string("224.0.130.21", "mcpitch.ny5.u21.u24.gap.aa");
    add_ip_name_from_string("224.0.130.22", "mcpitch.ny5.u25.u28.gap.aa");
    add_ip_name_from_string("224.0.130.23", "mcpitch.ny5.u29.u32.gap.aa");

    /* NY5 - EDGA - WAN C - Realtime */
    add_ip_name_from_string("224.0.130.32", "mcpitch.ny5.u1.u4.rt.ac");
    add_ip_name_from_string("224.0.130.33", "mcpitch.ny5.u5.u8.rt.ac");
    add_ip_name_from_string("224.0.130.34", "mcpitch.ny5.u9.u12.rt.ac");
    add_ip_name_from_string("224.0.130.35", "mcpitch.ny5.u13.u16.rt.ac");
    add_ip_name_from_string("224.0.130.36", "mcpitch.ny5.u17.u20.rt.ac");
    add_ip_name_from_string("224.0.130.37", "mcpitch.ny5.u21.u24.rt.ac");
    add_ip_name_from_string("224.0.130.38", "mcpitch.ny5.u25.u28.rt.ac");
    add_ip_name_from_string("224.0.130.39", "mcpitch.ny5.u29.u32.rt.ac");

    /* NY5 - EDGA - WAN C - Gap */
    add_ip_name_from_string("224.0.130.48", "mcpitch.ny5.u1.u4.gap.ac");
    add_ip_name_from_string("224.0.130.49", "mcpitch.ny5.u5.u8.gap.ac");
    add_ip_name_from_string("224.0.130.50", "mcpitch.ny5.u9.u12.gap.ac");
    add_ip_name_from_string("224.0.130.51", "mcpitch.ny5.u13.u16.gap.ac");
    add_ip_name_from_string("224.0.130.52", "mcpitch.ny5.u17.u20.gap.ac");
    add_ip_name_from_string("224.0.130.53", "mcpitch.ny5.u21.u24.gap.ac");
    add_ip_name_from_string("224.0.130.54", "mcpitch.ny5.u25.u28.gap.ac");
    add_ip_name_from_string("224.0.130.55", "mcpitch.ny5.u29.u32.gap.ac");

    /* NY5 - EDGA - GIG B - Realtime */
    add_ip_name_from_string("233.209.92.0", "mcpitch.ny5.u1.u4.rt.ab");
    add_ip_name_from_string("233.209.92.1", "mcpitch.ny5.u5.u8.rt.ab");
    add_ip_name_from_string("233.209.92.2", "mcpitch.ny5.u9.u12.rt.ab");
    add_ip_name_from_string("233.209.92.3", "mcpitch.ny5.u13.u16.rt.ab");
    add_ip_name_from_string("233.209.92.4", "mcpitch.ny5.u17.u20.rt.ab");
    add_ip_name_from_string("233.209.92.5", "mcpitch.ny5.u21.u24.rt.ab");
    add_ip_name_from_string("233.209.92.6", "mcpitch.ny5.u25.u28.rt.ab");
    add_ip_name_from_string("233.209.92.7", "mcpitch.ny5.u29.u32.rt.ab");

    /* NY5 - EDGA - GIG B - Gap */
    add_ip_name_from_string("233.209.92.16", "mcpitch.ny5.u1.u4.gap.ab");
    add_ip_name_from_string("233.209.92.17", "mcpitch.ny5.u5.u8.gap.ab");
    add_ip_name_from_string("233.209.92.18", "mcpitch.ny5.u9.u12.gap.ab");
    add_ip_name_from_string("233.209.92.19", "mcpitch.ny5.u13.u16.gap.ab");
    add_ip_name_from_string("233.209.92.20", "mcpitch.ny5.u17.u20.gap.ab");
    add_ip_name_from_string("233.209.92.21", "mcpitch.ny5.u21.u24.gap.ab");
    add_ip_name_from_string("233.209.92.22", "mcpitch.ny5.u25.u28.gap.ab");
    add_ip_name_from_string("233.209.92.23", "mcpitch.ny5.u29.u32.gap.ab");

    /* NY5 - EDGA - WAN D - Realtime */
    add_ip_name_from_string("233.209.92.32", "mcpitch.ny5.u1.u4.rt.ad");
    add_ip_name_from_string("233.209.92.33", "mcpitch.ny5.u5.u8.rt.ad");
    add_ip_name_from_string("233.209.92.34", "mcpitch.ny5.u9.u12.rt.ad");
    add_ip_name_from_string("233.209.92.35", "mcpitch.ny5.u13.u16.rt.ad");
    add_ip_name_from_string("233.209.92.36", "mcpitch.ny5.u17.u20.rt.ad");
    add_ip_name_from_string("233.209.92.37", "mcpitch.ny5.u21.u24.rt.ad");
    add_ip_name_from_string("233.209.92.38", "mcpitch.ny5.u25.u28.rt.ad");
    add_ip_name_from_string("233.209.92.39", "mcpitch.ny5.u29.u32.rt.ad");

    /* NY5 - EDGA - WAN D - Gap */
    add_ip_name_from_string("233.209.92.48", "mcpitch.ny5.u1.u4.gap.ad");
    add_ip_name_from_string("233.209.92.49", "mcpitch.ny5.u5.u8.gap.ad");
    add_ip_name_from_string("233.209.92.50", "mcpitch.ny5.u9.u12.gap.ad");
    add_ip_name_from_string("233.209.92.51", "mcpitch.ny5.u13.u16.gap.ad");
    add_ip_name_from_string("233.209.92.52", "mcpitch.ny5.u17.u20.gap.ad");
    add_ip_name_from_string("233.209.92.53", "mcpitch.ny5.u21.u24.gap.ad");
    add_ip_name_from_string("233.209.92.54", "mcpitch.ny5.u25.u28.gap.ad");
    add_ip_name_from_string("233.209.92.55", "mcpitch.ny5.u29.u32.gap.ad");

    /* CH4 - EDGA - WAN E - Realtime */
    add_ip_name_from_string("233.19.3.48", "mcpitch.ch4.u1.u4.rt.ae");
    add_ip_name_from_string("233.19.3.50", "mcpitch.ch4.u5.u8.rt.ae");
    add_ip_name_from_string("233.19.3.52", "mcpitch.ch4.u9.u12.rt.ae");
    add_ip_name_from_string("233.19.3.54", "mcpitch.ch4.u13.u16.rt.ae");
    add_ip_name_from_string("233.19.3.56", "mcpitch.ch4.u17.u20.rt.ae");
    add_ip_name_from_string("233.19.3.58", "mcpitch.ch4.u21.u24.rt.ae");
    add_ip_name_from_string("233.19.3.60", "mcpitch.ch4.u25.u28.rt.ae");
    add_ip_name_from_string("233.19.3.62", "mcpitch.ch4.u29.u32.rt.ae");

    /* CH4 - EDGA - WAN E - Gap */
    add_ip_name_from_string("233.19.3.49", "mcpitch.ny5.u1.u4.gap.ae");
    add_ip_name_from_string("233.19.3.51", "mcpitch.ny5.u5.u8.gap.ae");
    add_ip_name_from_string("233.19.3.53", "mcpitch.ny5.u9.u12.gap.ae");
    add_ip_name_from_string("233.19.3.55", "mcpitch.ny5.u13.u16.gap.ae");
    add_ip_name_from_string("233.19.3.57", "mcpitch.ny5.u17.u20.gap.ae");
    add_ip_name_from_string("233.19.3.59", "mcpitch.ny5.u21.u24.gap.ae");
    add_ip_name_from_string("233.19.3.61", "mcpitch.ny5.u25.u28.gap.ae");
    add_ip_name_from_string("233.19.3.63", "mcpitch.ny5.u29.u32.gap.ae");

    /* --------------------------------------------------------------------------------
     * EDGX Market
     * -------------------------------------------------------------------------------- */
    
    /* NY5 - EDGX - GIG A - Realtime */
    add_ip_name_from_string("224.0.130.64", "mcpitch.ny5.u1.u4.rt.xa");
    add_ip_name_from_string("224.0.130.65", "mcpitch.ny5.u5.u8.rt.xa");
    add_ip_name_from_string("224.0.130.66", "mcpitch.ny5.u9.u12.rt.xa");
    add_ip_name_from_string("224.0.130.67", "mcpitch.ny5.u13.u16.rt.xa");
    add_ip_name_from_string("224.0.130.68", "mcpitch.ny5.u17.u20.rt.xa");
    add_ip_name_from_string("224.0.130.69", "mcpitch.ny5.u21.u24.rt.xa");
    add_ip_name_from_string("224.0.130.70", "mcpitch.ny5.u25.u28.rt.xa");
    add_ip_name_from_string("224.0.130.71", "mcpitch.ny5.u29.u32.rt.xa");

    /* NY5 - EDGX - GIG A - Gap */
    add_ip_name_from_string("224.0.130.80", "mcpitch.ny5.u1.u4.gap.xa");
    add_ip_name_from_string("224.0.130.81", "mcpitch.ny5.u5.u8.gap.xa");
    add_ip_name_from_string("224.0.130.82", "mcpitch.ny5.u9.u12.gap.xa");
    add_ip_name_from_string("224.0.130.83", "mcpitch.ny5.u13.u16.gap.xa");
    add_ip_name_from_string("224.0.130.84", "mcpitch.ny5.u17.u20.gap.xa");
    add_ip_name_from_string("224.0.130.85", "mcpitch.ny5.u21.u24.gap.xa");
    add_ip_name_from_string("224.0.130.86", "mcpitch.ny5.u25.u28.gap.xa");
    add_ip_name_from_string("224.0.130.87", "mcpitch.ny5.u29.u32.gap.xa");

    /* NY5 - EDGX - WAN C - Realtime */
    add_ip_name_from_string("224.0.130.96", "mcpitch.ny5.u1.u4.rt.xc");
    add_ip_name_from_string("224.0.130.97", "mcpitch.ny5.u5.u8.rt.xc");
    add_ip_name_from_string("224.0.130.98", "mcpitch.ny5.u9.u12.rt.xc");
    add_ip_name_from_string("224.0.130.99", "mcpitch.ny5.u13.u16.rt.xc");
    add_ip_name_from_string("224.0.130.100", "mcpitch.ny5.u17.u20.rt.xc");
    add_ip_name_from_string("224.0.130.101", "mcpitch.ny5.u21.u24.rt.xc");
    add_ip_name_from_string("224.0.130.102", "mcpitch.ny5.u25.u28.rt.xc");
    add_ip_name_from_string("224.0.130.103", "mcpitch.ny5.u29.u32.rt.xc");

    /* NY5 - EDGX - WAN C - Gap */
    add_ip_name_from_string("224.0.130.112", "mcpitch.ny5.u1.u4.gap.xc");
    add_ip_name_from_string("224.0.130.113", "mcpitch.ny5.u5.u8.gap.xc");
    add_ip_name_from_string("224.0.130.114", "mcpitch.ny5.u9.u12.gap.xc");
    add_ip_name_from_string("224.0.130.115", "mcpitch.ny5.u13.u16.gap.xc");
    add_ip_name_from_string("224.0.130.116", "mcpitch.ny5.u17.u20.gap.xc");
    add_ip_name_from_string("224.0.130.117", "mcpitch.ny5.u21.u24.gap.xc");
    add_ip_name_from_string("224.0.130.118", "mcpitch.ny5.u25.u28.gap.xc");
    add_ip_name_from_string("224.0.130.119", "mcpitch.ny5.u29.u32.gap.xc");

    /* NY5 - EDGX - GIG B - Realtime */
    add_ip_name_from_string("233.209.92.64", "mcpitch.ny5.u1.u4.rt.xb");
    add_ip_name_from_string("233.209.92.65", "mcpitch.ny5.u5.u8.rt.xb");
    add_ip_name_from_string("233.209.92.66", "mcpitch.ny5.u9.u12.rt.xb");
    add_ip_name_from_string("233.209.92.67", "mcpitch.ny5.u13.u16.rt.xb");
    add_ip_name_from_string("233.209.92.68", "mcpitch.ny5.u17.u20.rt.xb");
    add_ip_name_from_string("233.209.92.69", "mcpitch.ny5.u21.u24.rt.xb");
    add_ip_name_from_string("233.209.92.70", "mcpitch.ny5.u25.u28.rt.xb");
    add_ip_name_from_string("233.209.92.71", "mcpitch.ny5.u29.u32.rt.xb");

    /* NY5 - EDGX - GIG B - Gap */
    add_ip_name_from_string("233.209.92.80", "mcpitch.ny5.u1.u4.gap.xb");
    add_ip_name_from_string("233.209.92.81", "mcpitch.ny5.u5.u8.gap.xb");
    add_ip_name_from_string("233.209.92.82", "mcpitch.ny5.u9.u12.gap.xb");
    add_ip_name_from_string("233.209.92.83", "mcpitch.ny5.u13.u16.gap.xb");
    add_ip_name_from_string("233.209.92.84", "mcpitch.ny5.u17.u20.gap.xb");
    add_ip_name_from_string("233.209.92.85", "mcpitch.ny5.u21.u24.gap.xb");
    add_ip_name_from_string("233.209.92.86", "mcpitch.ny5.u25.u28.gap.xb");
    add_ip_name_from_string("233.209.92.87", "mcpitch.ny5.u29.u32.gap.xb");

    /* NY5 - EDGX - WAN D - Realtime */
    add_ip_name_from_string("233.209.92.96", "mcpitch.ny5.u1.u4.rt.xd");
    add_ip_name_from_string("233.209.92.97", "mcpitch.ny5.u5.u8.rt.xd");
    add_ip_name_from_string("233.209.92.98", "mcpitch.ny5.u9.u12.rt.xd");
    add_ip_name_from_string("233.209.92.99", "mcpitch.ny5.u13.u16.rt.xd");
    add_ip_name_from_string("233.209.92.100", "mcpitch.ny5.u17.u20.rt.xd");
    add_ip_name_from_string("233.209.92.101", "mcpitch.ny5.u21.u24.rt.xd");
    add_ip_name_from_string("233.209.92.102", "mcpitch.ny5.u25.u28.rt.xd");
    add_ip_name_from_string("233.209.92.103", "mcpitch.ny5.u29.u32.rt.xd");

    /* NY5 - EDGX - WAN D - Gap */
    add_ip_name_from_string("233.209.92.112", "mcpitch.ny5.u1.u4.gap.xd");
    add_ip_name_from_string("233.209.92.113", "mcpitch.ny5.u5.u8.gap.xd");
    add_ip_name_from_string("233.209.92.114", "mcpitch.ny5.u9.u12.gap.xd");
    add_ip_name_from_string("233.209.92.115", "mcpitch.ny5.u13.u16.gap.xd");
    add_ip_name_from_string("233.209.92.116", "mcpitch.ny5.u17.u20.gap.xd");
    add_ip_name_from_string("233.209.92.117", "mcpitch.ny5.u21.u24.gap.xd");
    add_ip_name_from_string("233.209.92.118", "mcpitch.ny5.u25.u28.gap.xd");
    add_ip_name_from_string("233.209.92.119", "mcpitch.ny5.u29.u32.gap.xd");

    /* CH4 - EDGX - WAN E - Realtime */
    add_ip_name_from_string("233.19.3.64", "mcpitch.ch4.u1.u4.rt.xe");
    add_ip_name_from_string("233.19.3.66", "mcpitch.ch4.u5.u8.rt.xe");
    add_ip_name_from_string("233.19.3.68", "mcpitch.ch4.u9.u12.rt.xe");
    add_ip_name_from_string("233.19.3.70", "mcpitch.ch4.u13.u16.rt.xe");
    add_ip_name_from_string("233.19.3.72", "mcpitch.ch4.u17.u20.rt.xe");
    add_ip_name_from_string("233.19.3.74", "mcpitch.ch4.u21.u24.rt.xe");
    add_ip_name_from_string("233.19.3.76", "mcpitch.ch4.u25.u28.rt.xe");
    add_ip_name_from_string("233.19.3.78", "mcpitch.ch4.u29.u32.rt.xe");

    /* CH4 - EDGX - WAN E - Gap */
    add_ip_name_from_string("233.19.3.65", "mcpitch.ny5.u1.u4.gap.xe");
    add_ip_name_from_string("233.19.3.67", "mcpitch.ny5.u5.u8.gap.xe");
    add_ip_name_from_string("233.19.3.69", "mcpitch.ny5.u9.u12.gap.xe");
    add_ip_name_from_string("233.19.3.71", "mcpitch.ny5.u13.u16.gap.xe");
    add_ip_name_from_string("233.19.3.73", "mcpitch.ny5.u17.u20.gap.xe");
    add_ip_name_from_string("233.19.3.75", "mcpitch.ny5.u21.u24.gap.xe");
    add_ip_name_from_string("233.19.3.77", "mcpitch.ny5.u25.u28.gap.xe");
    add_ip_name_from_string("233.19.3.78", "mcpitch.ny5.u29.u32.gap.xe");

    /* --------------------------------------------------------------------------------
     * BZX Options Market
     * -------------------------------------------------------------------------------- */
    
    /* NJ2 - BZX Options - GIG A - Realtime */
    add_ip_name_from_string("224.0.62.96",  "mcpitch.nj2.u1.u4.rt.oa");
    add_ip_name_from_string("224.0.62.98",  "mcpitch.nj2.u5.u8.rt.oa");
    add_ip_name_from_string("224.0.62.100", "mcpitch.nj2.u9.u12.rt.oa");
    add_ip_name_from_string("224.0.62.102", "mcpitch.nj2.u13.u16.rt.oa");
    add_ip_name_from_string("224.0.62.104", "mcpitch.nj2.u17.u20.rt.oa");
    add_ip_name_from_string("224.0.62.106", "mcpitch.nj2.u21.u24.rt.oa");
    add_ip_name_from_string("224.0.62.108", "mcpitch.nj2.u25.u28.rt.oa");
    add_ip_name_from_string("224.0.62.110", "mcpitch.nj2.u29.u32.rt.oa");

    /* NJ2 - BZX Options - GIG A - Gap */
    add_ip_name_from_string("224.0.62.97",  "mcpitch.nj2.u1.u4.gap.oa");
    add_ip_name_from_string("224.0.62.99",  "mcpitch.nj2.u5.u8.gap.oa");
    add_ip_name_from_string("224.0.62.101", "mcpitch.nj2.u9.u12.gap.oa");
    add_ip_name_from_string("224.0.62.103", "mcpitch.nj2.u13.u16.gap.oa");
    add_ip_name_from_string("224.0.62.105", "mcpitch.nj2.u17.u20.gap.oa");
    add_ip_name_from_string("224.0.62.107", "mcpitch.nj2.u21.u24.gap.oa");
    add_ip_name_from_string("224.0.62.109", "mcpitch.nj2.u25.u28.gap.oa");
    add_ip_name_from_string("224.0.62.111", "mcpitch.nj2.u29.u32.gap.oa");

    /* NJ2 - BZX Options - WAN C - Realtime */
    add_ip_name_from_string("224.0.62.120", "mcpitch.nj2.u1.u4.rt.oc");
    add_ip_name_from_string("224.0.62.122", "mcpitch.nj2.u5.u8.rt.oc");
    add_ip_name_from_string("224.0.62.124", "mcpitch.nj2.u9.u12.rt.oc");
    add_ip_name_from_string("224.0.62.126", "mcpitch.nj2.u13.u16.rt.oc");
    add_ip_name_from_string("224.0.62.128", "mcpitch.nj2.u17.u20.rt.oc");
    add_ip_name_from_string("224.0.62.130", "mcpitch.nj2.u21.u24.rt.oc");
    add_ip_name_from_string("224.0.62.132", "mcpitch.nj2.u25.u28.rt.oc");
    add_ip_name_from_string("224.0.62.134", "mcpitch.nj2.u29.u32.rt.oc");

    /* NJ2 - BZX Options - WAN C - Gap */
    add_ip_name_from_string("224.0.62.121", "mcpitch.nj2.u1.u4.gap.oc");
    add_ip_name_from_string("224.0.62.123", "mcpitch.nj2.u5.u8.gap.oc");
    add_ip_name_from_string("224.0.62.125", "mcpitch.nj2.u9.u12.gap.oc");
    add_ip_name_from_string("224.0.62.127", "mcpitch.nj2.u13.u16.gap.oc");
    add_ip_name_from_string("224.0.62.129", "mcpitch.nj2.u17.u20.gap.oc");
    add_ip_name_from_string("224.0.62.131", "mcpitch.nj2.u21.u24.gap.oc");
    add_ip_name_from_string("224.0.62.133", "mcpitch.nj2.u25.u28.gap.oc");
    add_ip_name_from_string("224.0.62.135", "mcpitch.nj2.u29.u32.gap.oc");

    /* NJ2 - BZX Options - GIG B - Realtime */
    add_ip_name_from_string("233.19.3.160", "mcpitch.nj2.u1.u4.rt.ob");
    add_ip_name_from_string("233.19.3.162", "mcpitch.nj2.u5.u8.rt.ob");
    add_ip_name_from_string("233.19.3.164", "mcpitch.nj2.u9.u12.rt.ob");
    add_ip_name_from_string("233.19.3.166", "mcpitch.nj2.u13.u16.rt.ob");
    add_ip_name_from_string("233.19.3.168", "mcpitch.nj2.u17.u20.rt.ob");
    add_ip_name_from_string("233.19.3.170", "mcpitch.nj2.u21.u24.rt.ob");
    add_ip_name_from_string("233.19.3.172", "mcpitch.nj2.u25.u28.rt.ob");
    add_ip_name_from_string("233.19.3.174", "mcpitch.nj2.u29.u32.rt.ob");

    /* NJ2 - BZX Options - GIG B - Gap */
    add_ip_name_from_string("233.19.3.161", "mcpitch.nj2.u1.u4.gap.ob");
    add_ip_name_from_string("233.19.3.163", "mcpitch.nj2.u5.u8.gap.ob");
    add_ip_name_from_string("233.19.3.165", "mcpitch.nj2.u9.u12.gap.ob");
    add_ip_name_from_string("233.19.3.167", "mcpitch.nj2.u13.u16.gap.ob");
    add_ip_name_from_string("233.19.3.169", "mcpitch.nj2.u17.u20.gap.ob");
    add_ip_name_from_string("233.19.3.171", "mcpitch.nj2.u21.u24.gap.ob");
    add_ip_name_from_string("233.19.3.173", "mcpitch.nj2.u25.u28.gap.ob");
    add_ip_name_from_string("233.19.3.175", "mcpitch.nj2.u29.u32.gap.ob");

    /* NJ2 - BZX Options - WAN D - Realtime */
    add_ip_name_from_string("233.19.3.176", "mcpitch.nj2.u1.u4.rt.od");
    add_ip_name_from_string("233.19.3.178", "mcpitch.nj2.u5.u8.rt.od");
    add_ip_name_from_string("233.19.3.180", "mcpitch.nj2.u9.u12.rt.od");
    add_ip_name_from_string("233.19.3.182", "mcpitch.nj2.u13.u16.rt.od");
    add_ip_name_from_string("233.19.3.184", "mcpitch.nj2.u17.u20.rt.od");
    add_ip_name_from_string("233.19.3.186", "mcpitch.nj2.u21.u24.rt.od");
    add_ip_name_from_string("233.19.3.188", "mcpitch.nj2.u25.u28.rt.od");
    add_ip_name_from_string("233.19.3.190", "mcpitch.nj2.u29.u32.rt.od");

    /* NJ2 - BZX Options - WAN D - Gap */
    add_ip_name_from_string("233.19.3.177", "mcpitch.nj2.u1.u4.gap.od");
    add_ip_name_from_string("233.19.3.179", "mcpitch.nj2.u5.u8.gap.od");
    add_ip_name_from_string("233.19.3.181", "mcpitch.nj2.u9.u12.gap.od");
    add_ip_name_from_string("233.19.3.183", "mcpitch.nj2.u13.u16.gap.od");
    add_ip_name_from_string("233.19.3.185", "mcpitch.nj2.u17.u20.gap.od");
    add_ip_name_from_string("233.19.3.187", "mcpitch.nj2.u21.u24.gap.od");
    add_ip_name_from_string("233.19.3.189", "mcpitch.nj2.u25.u28.gap.od");
    add_ip_name_from_string("233.19.3.191", "mcpitch.nj2.u29.u32.gap.od");

    /* NY5 - BZX Options - GIG A - Realtime */
    add_ip_name_from_string("224.0.131.0", "mcpitch.ny5.u1.u4.rt.oa");
    add_ip_name_from_string("224.0.131.1", "mcpitch.ny5.u5.u8.rt.oa");
    add_ip_name_from_string("224.0.131.2", "mcpitch.ny5.u9.u12.rt.oa");
    add_ip_name_from_string("224.0.131.3", "mcpitch.ny5.u13.u16.rt.oa");
    add_ip_name_from_string("224.0.131.4", "mcpitch.ny5.u17.u20.rt.oa");
    add_ip_name_from_string("224.0.131.5", "mcpitch.ny5.u21.u24.rt.oa");
    add_ip_name_from_string("224.0.131.6", "mcpitch.ny5.u25.u28.rt.oa");
    add_ip_name_from_string("224.0.131.7", "mcpitch.ny5.u29.u32.rt.oa");

    /* NY5 - BZX Options - GIG A - Gap */
    add_ip_name_from_string("224.0.131.16", "mcpitch.ny5.u1.u4.gap.oa");
    add_ip_name_from_string("224.0.131.17", "mcpitch.ny5.u5.u8.gap.oa");
    add_ip_name_from_string("224.0.131.18", "mcpitch.ny5.u9.u12.gap.oa");
    add_ip_name_from_string("224.0.131.19", "mcpitch.ny5.u13.u16.gap.oa");
    add_ip_name_from_string("224.0.131.20", "mcpitch.ny5.u17.u20.gap.oa");
    add_ip_name_from_string("224.0.131.21", "mcpitch.ny5.u21.u24.gap.oa");
    add_ip_name_from_string("224.0.131.22", "mcpitch.ny5.u25.u28.gap.oa");
    add_ip_name_from_string("224.0.131.23", "mcpitch.ny5.u29.u32.gap.oa");

    /* NY5 - BZX Options - WAN C - Realtime */
    add_ip_name_from_string("224.0.131.32", "mcpitch.ny5.u1.u4.rt.oc");
    add_ip_name_from_string("224.0.131.33", "mcpitch.ny5.u5.u8.rt.oc");
    add_ip_name_from_string("224.0.131.34", "mcpitch.ny5.u9.u12.rt.oc");
    add_ip_name_from_string("224.0.131.35", "mcpitch.ny5.u13.u16.rt.oc");
    add_ip_name_from_string("224.0.131.36", "mcpitch.ny5.u17.u20.rt.oc");
    add_ip_name_from_string("224.0.131.37", "mcpitch.ny5.u21.u24.rt.oc");
    add_ip_name_from_string("224.0.131.38", "mcpitch.ny5.u25.u28.rt.oc");
    add_ip_name_from_string("224.0.131.39", "mcpitch.ny5.u29.u32.rt.oc");

    /* NY5 - BZX Options - WAN C - Gap */
    add_ip_name_from_string("224.0.131.48", "mcpitch.ny5.u1.u4.gap.oc");
    add_ip_name_from_string("224.0.131.49", "mcpitch.ny5.u5.u8.gap.oc");
    add_ip_name_from_string("224.0.131.50", "mcpitch.ny5.u9.u12.gap.oc");
    add_ip_name_from_string("224.0.131.51", "mcpitch.ny5.u13.u16.gap.oc");
    add_ip_name_from_string("224.0.131.52", "mcpitch.ny5.u17.u20.gap.oc");
    add_ip_name_from_string("224.0.131.53", "mcpitch.ny5.u21.u24.gap.oc");
    add_ip_name_from_string("224.0.131.54", "mcpitch.ny5.u25.u28.gap.oc");
    add_ip_name_from_string("224.0.131.55", "mcpitch.ny5.u29.u32.gap.oc");

    /* NY5 - BZX Options - GIG B - Realtime */
    add_ip_name_from_string("233.130.124.0", "mcpitch.ny5.u1.u4.rt.ob");
    add_ip_name_from_string("233.130.124.1", "mcpitch.ny5.u5.u8.rt.ob");
    add_ip_name_from_string("233.130.124.2", "mcpitch.ny5.u9.u12.rt.ob");
    add_ip_name_from_string("233.130.124.3", "mcpitch.ny5.u13.u16.rt.ob");
    add_ip_name_from_string("233.130.124.4", "mcpitch.ny5.u17.u20.rt.ob");
    add_ip_name_from_string("233.130.124.5", "mcpitch.ny5.u21.u24.rt.ob");
    add_ip_name_from_string("233.130.124.6", "mcpitch.ny5.u25.u28.rt.ob");
    add_ip_name_from_string("233.130.124.7", "mcpitch.ny5.u29.u32.rt.ob");

    /* NY5 - BZX Options - GIG B - Gap */
    add_ip_name_from_string("233.130.124.16", "mcpitch.ny5.u1.u4.gap.ob");
    add_ip_name_from_string("233.130.124.17", "mcpitch.ny5.u5.u8.gap.ob");
    add_ip_name_from_string("233.130.124.18", "mcpitch.ny5.u9.u12.gap.ob");
    add_ip_name_from_string("233.130.124.19", "mcpitch.ny5.u13.u16.gap.ob");
    add_ip_name_from_string("233.130.124.20", "mcpitch.ny5.u17.u20.gap.ob");
    add_ip_name_from_string("233.130.124.21", "mcpitch.ny5.u21.u24.gap.ob");
    add_ip_name_from_string("233.130.124.22", "mcpitch.ny5.u25.u28.gap.ob");
    add_ip_name_from_string("233.130.124.23", "mcpitch.ny5.u29.u32.gap.ob");

    /* NY5 - BZX Options - WAN D - Realtime */
    add_ip_name_from_string("233.130.124.32", "mcpitch.ny5.u1.u4.rt.od");
    add_ip_name_from_string("233.130.124.33", "mcpitch.ny5.u5.u8.rt.od");
    add_ip_name_from_string("233.130.124.34", "mcpitch.ny5.u9.u12.rt.od");
    add_ip_name_from_string("233.130.124.35", "mcpitch.ny5.u13.u16.rt.od");
    add_ip_name_from_string("233.130.124.36", "mcpitch.ny5.u17.u20.rt.od");
    add_ip_name_from_string("233.130.124.37", "mcpitch.ny5.u21.u24.rt.od");
    add_ip_name_from_string("233.130.124.38", "mcpitch.ny5.u25.u28.rt.od");
    add_ip_name_from_string("233.130.124.39", "mcpitch.ny5.u29.u32.rt.od");

    /* NY5 - BZX Options - WAN D - Gap */
    add_ip_name_from_string("233.130.124.48", "mcpitch.ny5.u1.u4.gap.od");
    add_ip_name_from_string("233.130.124.49", "mcpitch.ny5.u5.u8.gap.od");
    add_ip_name_from_string("233.130.124.50", "mcpitch.ny5.u9.u12.gap.od");
    add_ip_name_from_string("233.130.124.51", "mcpitch.ny5.u13.u16.gap.od");
    add_ip_name_from_string("233.130.124.52", "mcpitch.ny5.u17.u20.gap.od");
    add_ip_name_from_string("233.130.124.53", "mcpitch.ny5.u21.u24.gap.od");
    add_ip_name_from_string("233.130.124.54", "mcpitch.ny5.u25.u28.gap.od");
    add_ip_name_from_string("233.130.124.55", "mcpitch.ny5.u29.u32.gap.od");

    /* CH4 - BZX Options - WAN E - Realtime */
    add_ip_name_from_string("233.19.3.96",  "mcpitch.ch4.u1.u4.rt.oe");
    add_ip_name_from_string("233.19.3.98",  "mcpitch.ch4.u5.u8.rt.oe");
    add_ip_name_from_string("233.19.3.100", "mcpitch.ch4.u9.u12.rt.oe");
    add_ip_name_from_string("233.19.3.102", "mcpitch.ch4.u13.u16.rt.oe");
    add_ip_name_from_string("233.19.3.104", "mcpitch.ch4.u17.u20.rt.oe");
    add_ip_name_from_string("233.19.3.106", "mcpitch.ch4.u21.u24.rt.oe");
    add_ip_name_from_string("233.19.3.108", "mcpitch.ch4.u25.u28.rt.oe");
    add_ip_name_from_string("233.19.3.110", "mcpitch.ch4.u29.u32.rt.oe");

    /* CH4 - BZX Options - WAN E - Gap */
    add_ip_name_from_string("233.19.3.97",  "mcpitch.ny5.u1.u4.gap.oe");
    add_ip_name_from_string("233.19.3.99",  "mcpitch.ny5.u5.u8.gap.oe");
    add_ip_name_from_string("233.19.3.101", "mcpitch.ny5.u9.u12.gap.oe");
    add_ip_name_from_string("233.19.3.103", "mcpitch.ny5.u13.u16.gap.oe");
    add_ip_name_from_string("233.19.3.105", "mcpitch.ny5.u17.u20.gap.oe");
    add_ip_name_from_string("233.19.3.107", "mcpitch.ny5.u21.u24.gap.oe");
    add_ip_name_from_string("233.19.3.109", "mcpitch.ny5.u25.u28.gap.oe");
    add_ip_name_from_string("233.19.3.111", "mcpitch.ny5.u29.u32.gap.oe");
}
