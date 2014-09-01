/* packet-mcastpitch.c
 * Routines for BATS Multicast PITCH.
 * Copyright 2010-2014, Eric Crampton <ecrampton@batstrading.com>
 *
 * $Id$
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

int proto_mcastpitch = -1;
static dissector_handle_t mcastpitch_handle;

static int hf_mcastpitch_hdr_length            = -1;
static int hf_mcastpitch_hdr_count             = -1;
static int hf_mcastpitch_hdr_unit              = -1;
static int hf_mcastpitch_hdr_sequence          = -1;
static int hf_mcastpitch_msg_length            = -1;
static int hf_mcastpitch_msg_type              = -1;
static int hf_mcastpitch_time                  = -1;
static int hf_mcastpitch_time_offset           = -1;
static int hf_mcastpitch_order_id              = -1;
static int hf_mcastpitch_side                  = -1;
static int hf_mcastpitch_long_quantity         = -1;
static int hf_mcastpitch_quantity8             = -1;
static int hf_mcastpitch_symbol6               = -1;
static int hf_mcastpitch_long_price            = -1;
static int hf_mcastpitch_short_quantity        = -1;
static int hf_mcastpitch_short_price           = -1;
static int hf_mcastpitch_executed_shares       = -1;
static int hf_mcastpitch_execution_id          = -1;
static int hf_mcastpitch_trade_id              = -1;
static int hf_mcastpitch_remaining_shares      = -1;
static int hf_mcastpitch_long_canceled_shares  = -1;
static int hf_mcastpitch_short_canceled_shares = -1;
static int hf_mcastpitch_symbol8               = -1;
static int hf_mcastpitch_add_flags             = -1;
static int hf_mcastpitch_osi_symbol            = -1;
static int hf_mcastpitch_session_sub_id        = -1;
static int hf_mcastpitch_username              = -1;
static int hf_mcastpitch_filler                = -1;
static int hf_mcastpitch_password              = -1;
static int hf_mcastpitch_login_response_type   = -1;
static int hf_mcastpitch_halt_status           = -1;
static int hf_mcastpitch_reg_sho_action        = -1;
static int hf_mcastpitch_reserved1             = -1;
static int hf_mcastpitch_reserved2             = -1;
static int hf_mcastpitch_auction_type          = -1;
static int hf_mcastpitch_reference_price       = -1;
static int hf_mcastpitch_buy_shares            = -1;
static int hf_mcastpitch_sell_shares           = -1;
static int hf_mcastpitch_indicative_price      = -1;
static int hf_mcastpitch_auction_only_price    = -1;
static int hf_mcastpitch_sequence              = -1;
static int hf_mcastpitch_order_count           = -1;
static int hf_mcastpitch_status                = -1;
static int hf_mcastpitch_unit                  = -1;
static int hf_mcastpitch_count                 = -1;
static int hf_mcastpitch_measurement_type      = -1;
static int hf_mcastpitch_begin_time            = -1;
static int hf_mcastpitch_end_time              = -1;
static int hf_mcastpitch_minimum               = -1;
static int hf_mcastpitch_maximum               = -1;
static int hf_mcastpitch_average               = -1;
static int hf_mcastpitch_standard_deviation    = -1;
static int hf_mcastpitch_mode                  = -1;
static int hf_mcastpitch_99_9_percentile       = -1;
static int hf_mcastpitch_99_percentile         = -1;
static int hf_mcastpitch_95_percentile         = -1;
static int hf_mcastpitch_90_percentile         = -1;
static int hf_mcastpitch_75_percentile         = -1;
static int hf_mcastpitch_50_percentile         = -1;
static int hf_mcastpitch_25_percentile         = -1;
static int hf_mcastpitch_trade_time            = -1;
static int hf_mcastpitch_exec_venue            = -1;
static int hf_mcastpitch_traded_currency       = -1;
static int hf_mcastpitch_trade_report_flags    = -1;
static int hf_mcastpitch_participant_id        = -1;
static int hf_mcastpitch_trade_flags           = -1;
static int hf_mcastpitch_execution_flags       = -1;
static int hf_mcastpitch_statistic_type        = -1;
static int hf_mcastpitch_price_determination   = -1;

static gint ett_mcastpitch = -1;

static expert_field ei_mcastpitch_out_of_sequence = EI_INIT;

static const gint SEQUENCED_UNIT_HEADER_LEN                = 8;
static const gint LOGIN_MESSAGE_LEN                        = 22;
static const gint LOGIN_RESPONSE_MESSAGE_LEN               = 3;
static const gint GAP_REQUEST_MESSAGE_LEN                  = 9;
static const gint GAP_RESPONSE_MESSAGE_LEN                 = 10;
static const gint TIME_MESSAGE_LEN                         = 6;
static const gint ADD_ORDER_LONG_EU_MESSAGE_LEN            = 35;
static const gint ADD_ORDER_LONG_US_MESSAGE_LEN            = 34;
static const gint ADD_ORDER_SHORT_EU_MESSAGE_LEN           = 25;
static const gint ADD_ORDER_SHORT_US_MESSAGE_LEN           = 26;
static const gint ORDER_EXECUTED_EU_MESSAGE_LEN            = 29;
static const gint ORDER_EXECUTED_US_MESSAGE_LEN            = 26;
static const gint ORDER_EXECUTED_AT_PRICE_SIZE_EU_MESSAGE_LEN = 41;
static const gint ORDER_EXECUTED_AT_PRICE_SIZE_US_MESSAGE_LEN = 38;
static const gint REDUCE_SIZE_LONG_MESSAGE_LEN             = 18;
static const gint REDUCE_SIZE_SHORT_MESSAGE_LEN            = 16;
static const gint MODIFY_ORDER_LONG_EU_MESSAGE_LEN         = 26;
static const gint MODIFY_ORDER_LONG_US_MESSAGE_LEN         = 27;
static const gint MODIFY_ORDER_SHORT_EU_MESSAGE_LEN        = 18;
static const gint MODIFY_ORDER_SHORT_US_MESSAGE_LEN        = 19;
static const gint DELETE_ORDER_MESSAGE_LEN                 = 14;
static const gint TRADE_LONG_EU_MESSAGE_LEN                = 47;
static const gint TRADE_LONG_US_MESSAGE_LEN                = 41;
static const gint TRADE_SHORT_EU_MESSAGE_LEN               = 37;
static const gint TRADE_SHORT_US_MESSAGE_LEN               = 33;
static const gint TRADE_BREAK_MESSAGE_LEN                  = 14;
static const gint TRADE_REPORT_MESSAGE_LEN                 = 64;
static const gint END_OF_SESSION_MESSAGE_LEN               = 6;
static const gint SYMBOL_MAPPING_MESSAGE_LEN               = 29;
static const gint TRADING_STATUS_MESSAGE_LEN               = 18;
static const gint ADD_ORDER_EXPANDED_US_MESSAGE_LEN        = 36;
static const gint ADD_ORDER_EXPANDED_EU_MESSAGE_LEN        = 40;
static const gint TRADE_EXPANDED_MESSAGE_LEN               = 43;
static const gint SPIN_IMAGE_AVAILABLE_MESSAGE_LEN         = 6;
static const gint SPIN_REQUEST_MESSAGE_LEN                 = 6;
static const gint SPIN_RESPONSE_MESSAGE_LEN                = 11;
static const gint SPIN_FINISHED_MESSAGE_LEN                = 6;
static const gint AUCTION_UPDATE_MESSAGE_LEN               = 47;
static const gint AUCTION_SUMMARY_MESSAGE_LEN              = 27;
static const gint UNIT_CLEAR_MESSAGE_LEN                   = 6;
static const gint LATENCY_STAT_MESSAGE_LEN                 = 112;
static const gint STATISTICS_MESSAGE_LEN                   = 24;

static const value_string mcastPitchAuctionTypes[] = {
    { 'O', "Opening Auction" },
    { 'C', "Closing Auction" },
    { 'H', "Halt Auction" },
    { 'I', "IPO Auction" },
    { 'V', "Volatility Auction" },
    { 0, NULL },
};
 
static const value_string mcastPitchStatisticTypes[] = {
    { 'C', "Closing Price" },
    { 'H', "High Price" },
    { 'L', "Low Price" },
    { 'O', "Opening Price" },
    { 'P', "Previous Closing Price" },
    { 0, NULL },
};

static const value_string mcastPitchPriceDeterminationTypes[] = {
    { '0', "Normal" },
    { '1', "Manual" },
    { 0, NULL },
};

static const value_string mcastPitchTradingStatusTypes[] = {
    { 'T', "Trading" },
    { 'H', "Halted" },
    { 'Q', "Quote-Only" },
    { 'R', "Off-Book Reporting" },
    { 'C', "Closed" },
    { 'S', "Suspension" },
    { 'N', "No Reference Price" },
    { 'O', "Opening Auction" },
    { 'E', "Closing Auction" },
    { 'V', "Volatility Interruption" },
    { 'M', "Market Order Imbalance" },
    { 'P', "Price Monitoring Extension" },
    { 0, NULL },
};

#define MCP_OUT_OF_SEQUENCE 0x0001

typedef struct mcp_frame_data{
    guint32 expected_sequence;
    guint16 flags;
} mcp_frame_data_t;

typedef struct mcp_analysis {
    /* Next expected sequence number */     
    guint32 next_sequence;

    /* This pointer is NULL or points to a mcp_frame_data struct if this packet
     * has "interesting" properties e.g. out-of-sequence
     */ 
    mcp_frame_data_t *fd;

    /* This structure contains a tree of "interesting" frame data keyed by the
     * frame number
     */
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

    proto_tree_add_item(m_tree, hf_mcastpitch_msg_length,          tvb, *offset,      1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_msg_type,            tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_login_response_type, tvb, *offset + 2,  1, TRUE);
    
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

    proto_tree_add_item(m_tree, hf_mcastpitch_msg_length, tvb, *offset,      1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_msg_type,   tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_unit,       tvb, *offset + 2,  1, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_sequence,   tvb, *offset + 3,  4, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_count,      tvb, *offset + 7,  2, TRUE);
    proto_tree_add_item(m_tree, hf_mcastpitch_status,     tvb, *offset + 9,  1, TRUE);
    
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
    proto_tree_add_item      (msg_tree, hf_mcastpitch_add_flags,     tvb, *offset + 26, 1, TRUE);
    
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

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,    tvb, *offset,     1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,      tvb, *offset + 1, 1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_symbol6,       tvb, *offset + 2, 6, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_osi_symbol,    tvb, *offset + 8, 21, TRUE);

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
    proto_tree_add_item(msg_tree, hf_mcastpitch_halt_status,    tvb, *offset + 14, 1, TRUE);
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

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,      1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,  1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_sequence,       tvb, *offset + 2,  4, TRUE);

    *offset = *offset + SPIN_FINISHED_MESSAGE_LEN;
    
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
    proto_tree_add_item(msg_tree, hf_mcastpitch_order_count,    tvb, *offset + 6,  4, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_status,         tvb, *offset + 10, 1, TRUE);

    *offset = *offset + SPIN_RESPONSE_MESSAGE_LEN;
    
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
        printf("allocated mcpa=%p\n", mcpa);
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
            printf("allocated mcpa=%p\n", mcpa);
            mcpa->next_sequence = 0;
            mcpa->fd = NULL;
            mcpa->frame_table = wmem_tree_new(wmem_file_scope());
            conversation_add_proto_data(conv, proto_mcastpitch, (void *)mcpa);
        }
    }

    printf("returning mcpa=%p\n", mcpa);

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

    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_length,     tvb, *offset,       1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_msg_type,       tvb, *offset + 1,   1, TRUE);
    proto_tree_add_item(msg_tree, hf_mcastpitch_time_offset,    tvb, *offset + 2,   4, TRUE);

    *offset = *offset + UNIT_CLEAR_MESSAGE_LEN;

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
        if (mcpa->next_sequence && mcpa->next_sequence != hdr_sequence) {
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
    mcastpitch_handle = new_create_dissector_handle(dissect_mcastpitch, proto_mcastpitch);
    dissector_add_handle("udp.port", mcastpitch_handle);
    dissector_add_handle("tcp.port", mcastpitch_handle);
}

void
proto_register_mcastpitch(void)
{
	static hf_register_info hf[] = {
            { &hf_mcastpitch_hdr_length,            { "Hdr Length",              "mcastpitch.hdr_length",          FT_UINT16, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_hdr_count,             { "Hdr Count",               "mcastpitch.hdr_count",           FT_UINT8,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_hdr_unit,              { "Hdr Unit",                "mcastpitch.hdr_unit",            FT_UINT8,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_hdr_sequence,          { "Hdr Sequence",            "mcastpitch.hdr_sequence",        FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_msg_length,            { "Msg Length",              "mcastpitch.msg_length",          FT_UINT8,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_msg_type,              { "Msg Type",                "mcastpitch.msg_type",            FT_UINT8,  BASE_HEX,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_time,                  { "Time",                    "mcastpitch.time",                FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_time_offset,           { "Time Offset",             "mcastpitch.time_offset",         FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_order_id,              { "Order ID",                "mcastpitch.order_id",            FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_side,                  { "Side",                    "mcastpitch.side",                FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_long_quantity,         { "Quantity (Long)",         "mcastpitch.qty",                 FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_quantity8,             { "Quantity (Long)",         "mcastpitch.qty",                 FT_UINT64, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_symbol6,               { "Symbol",                  "mcastpitch.symbol",              FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_long_price,            { "Price (Long)",            "mcastpitch.price",               FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_short_quantity,        { "Quantity (Short)",        "mcastpitch.qty",                 FT_UINT16, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_short_price,           { "Price (Short)",           "mcastpitch.price",               FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_executed_shares,       { "Executed Shares",         "mcastpitch.executed_shares",     FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_execution_id,          { "Execution ID",            "mcastpitch.execution_id",        FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_trade_id,              { "Trade ID",                "mcastpitch.trade_id",            FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_remaining_shares,      { "Remaining Shares",        "mcastpitch.remaining_shares",    FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_long_canceled_shares,  { "Canceled Shares (Long)",  "mcastpitch.canceled_shares",     FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_short_canceled_shares, { "Canceled Shares (Short)", "mcastpitch.canceled_shares",     FT_UINT16, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_symbol8,               { "Symbol",                  "mcastpitch.symbol",              FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_add_flags,             { "Add Flags",               "mcastpitch.add_flags",           FT_UINT8,  BASE_HEX,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_osi_symbol,            { "OSI Symbol",              "mcastpitch.osi_symbol",          FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_session_sub_id,        { "Session Sub ID",          "mcastpitch.session_sub_id",      FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_username,              { "Username",                "mcastpitch.username",            FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_filler,                { "Filler",                  "mcastpitch.filler",              FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_password,              { "Password",                "mcastpitch.password",            FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_login_response_type,   { "Login Response Type",     "mcastpitch.login_response_type", FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_halt_status,           { "Halt Status",             "mcastpitch.halt_status",         FT_UINT8,  BASE_DEC,     mcastPitchTradingStatusTypes, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_reg_sho_action,        { "Reg SHO Action",          "mcastpitch.reg_sho_action",      FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_reserved1,             { "Reserved 1",              "mcastpitch.reserved1",           FT_UINT8,  BASE_HEX,     NULL, 0x0, NULL, HFILL } }, 
            { &hf_mcastpitch_reserved2,             { "Reserved 2",              "mcastpitch.reserved2",           FT_UINT8,  BASE_HEX,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_auction_type,          { "Auction Type",            "mcastpitch.auction_type",        FT_UINT8,  BASE_DEC,     mcastPitchAuctionTypes, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_reference_price,       { "Reference Price",         "mcastpitch.reference_price",     FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_buy_shares,            { "Buy Shares",              "mcastpitch.buy_shares",          FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_sell_shares,           { "Sell Shares",             "mcastpitch.sell_shares",         FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_indicative_price,      { "Indicative Price",        "mcastpitch.indicative_price",    FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_auction_only_price,    { "Auction Only Price",      "mcastpitch.auction_only_price",  FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_status,                { "Status",                  "mcastpitch.auction_only_price",  FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_unit,                  { "Unit",                    "mcastpitch.unit",                FT_UINT8,  BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_count,                 { "Count",                   "mcastpitch.count",               FT_UINT16, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_measurement_type,      { "Measurement Type",        "mcastpitch.measurement_type",    FT_UINT8,  BASE_HEX,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_begin_time,            { "Begin Time",              "mcastpitch.begin_time",          FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_end_time,              { "End Time",                "mcastpitch.end_time",            FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_sequence,              { "Sequence",                "mcastpitch.sequence",            FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_order_count,           { "Order Count",             "mcastpitch.order_count",         FT_UINT32, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_minimum,               { "Minimum",                 "mcastpitch.minimum",             FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_maximum,               { "Maximum",                 "mcastpitch.maximum",             FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_average,               { "Average",                 "mcastpitch.average",             FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_standard_deviation,    { "Standard Deviation",      "mcastpitch.standard_deviation",  FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_mode,                  { "Mode",                    "mcastpitch.mode",                FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_99_9_percentile,       { "99.9 Percentile",         "mcastpitch.99_9_percentile",     FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_99_percentile,         { "99 Percentile",           "mcastpitch.99_percentile",       FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_95_percentile,         { "95 Percentile",           "mcastpitch.95_percentile",       FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_90_percentile,         { "90 Percentile",           "mcastpitch.90_percentile",       FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_75_percentile,         { "75 Percentile",           "mcastpitch.75_percentile",       FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_50_percentile,         { "50 Percentile (Median)",  "mcastpitch.50_percentile",       FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_25_percentile,         { "25 Percentile",           "mcastpitch.25_percentile",       FT_DOUBLE, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_trade_time,            { "Trade Time",              "mcastpitch.trade_time",          FT_UINT64, BASE_DEC,     NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_exec_venue,            { "Execution Venue",         "mcastpitch.exec_venue",          FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_traded_currency,       { "Traded Currency",         "mcastpitch.traded_currency",     FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_trade_report_flags,    { "Trade Report Flags",      "mcastpitch.trade_report_flags",  FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_participant_id,        { "Participant ID",          "mcastpitch.participant_id",      FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_trade_flags,           { "Trade Flags",             "mcastpitch.trade_flags",         FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_execution_flags,       { "Execution Flags",         "mcastpitch.execution_flags",     FT_STRING, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_statistic_type,        { "Statistic Type",          "mcastpitch.statistic_type",      FT_UINT8,  BASE_DEC,     mcastPitchStatisticTypes, 0x0, NULL, HFILL } },
            { &hf_mcastpitch_price_determination,   { "Price Determination",     "mcastpitch.price_determination", FT_UINT8,  BASE_DEC,     mcastPitchPriceDeterminationTypes, 0x0, NULL, HFILL } },
	};

	static gint *ett[] = {
		&ett_mcastpitch
	};

        static ei_register_info ei[] = {
            { &ei_mcastpitch_out_of_sequence, { "mcastpitch.out_of_sequence", PI_SEQUENCE, PI_WARN, "Out-of-sequence", EXPFILL }},
        };
        
        expert_module_t *expert_mcastpitch;
        
	proto_mcastpitch = proto_register_protocol (
		"Multicast PITCH",      /* name */
		"BATS Multicast PITCH",	/* short name */
		"mcastpitch"		/* abbrev */
		);

	new_register_dissector("mcastpitch", dissect_mcastpitch, proto_mcastpitch);

	proto_register_field_array(proto_mcastpitch, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
        prefs_register_protocol(proto_mcastpitch, NULL);
        expert_mcastpitch = expert_register_protocol(proto_mcastpitch);
        expert_register_field_array(expert_mcastpitch, ei, array_length(ei));
}
