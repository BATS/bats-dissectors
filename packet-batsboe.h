#ifndef __PACKET_BATSBOE_H__
#define __PACKET_BATSBOE_H__

static const gint MESSAGE_HEADER_LEN                = 10;
static const gint LOGIN_REQUEST_MIN_LEN             = 118;
static const gint LOGIN_RESPONSE_MIN_LEN            = 165;
static const gint REPLAY_COMPLETE_LEN               = 10;
static const gint ORDER_CANCELLED_MIN_LEN           = 47;

static const value_string boeMessageTypeStrings[] = {
    { 0x01, "Login Request" },
    { 0x02, "Logout Request" },
    { 0x03, "Client Heartbeat" },
    { 0x04, "New Order" },
    { 0x05, "Cancel Order" },
    { 0x06, "Modify Order" },
    { 0x07, "Login Response" },
    { 0x08, "Logout" },
    { 0x09, "Server Heartbeat" },
    { 0x13, "Replay Complete" },
    { 0x0A, "Order Acknowledgement" },
    { 0x0B, "Order Rejected" },
    { 0x0C, "Order Modified" },
    { 0x0D, "Order Restated" },
    { 0x0E, "User Modify Rejected" },
    { 0x0F, "Order Cancelled" },
    { 0x10, "Cancel Rejected" },
    { 0x11, "Order Execution" },
    { 0x12, "Trade Cancel or Correct" },
    { 0x13, "Replay Complete" },
    { 0x14, "Bulk Order" },
    { 0x15, "Bulk Order Acknowledgement" },
    { 0x1C, "Bulk Order Extended" },
    { 0x1D, "Bulk Order Acknowledgement Extended" },
    { 0, NULL },
};

static const value_string boeNoUnspecifiedUnitReplayStrings[] = {
    { 0x00, "False (Replay Unspecified Units)" },
    { 0x01, "True (Suppress Unspecified Units Replay)" },
    { 0, NULL },
};

static const value_string boeLoginResponseStatusStrings[] = {
    { 'A', "Login Accepted" },
    { 'N', "Not Authorized" },
    { 'D', "Session is Disabled" },
    { 'B', "Session is in Use" },
    { 'S', "Invalid Session" },
    { 'Q', "Sequence Ahead in Login Message" },
    { 'I', "Invalid Unit Given in Login Message" },
    { 'F', "Invalid Return Bitfield in Login Message" },
    { 0, NULL },
};

static const value_string boeCancelReasonStrings[] = {
    { 'A', "Admin" },
    { 'D', "Duplicate ClOrdID" },
    { 'L', "Price Exceeds Cross Range" },
    { 'N', "Ran Out of Liquidity to Execute Against" },
    { 'R', "Routing Unavailable" },
    { 'U', "User Requested" },
    { 'V', "Would Wash" },
    { 'X', "Order Expired" },
    { 'Z', "Unforeseen Reason" },
    { 'u', "User Requested (delayed due to order being route pending)" },
    { 0, NULL },
};

static const value_string boeSideStrings[] = {
    { '1', "Buy" },
    { '2', "Sell" },
    { 0, NULL },
};

static const value_string boeExecInstStrings[] = {
    { 'P', "Market Peg" },
    { 'R', "Primary Peg" },
    { 'M', "Midpoint" },
    { 'm', "Midpoint No Lock" },
    { 'L', "Alternate Midpoint" },
    { 'c', "BATS Market on Close" },
    { 'u', "BATS + DRT (US) or BATS + External Dark Only (Europe)" },
    { 'v', "Force DRT (US) or BATS + External Dark + Lit (Europe)" },
    { 'w', "Do Not DRT (US) or BATS + External Lit Only (Europe)" },
    { 'f', "Intermarket Sweep" },
    { '\0', "No Special Handling" },
    { 0, NULL },
};

static const value_string boeOrdTypeStrings[] = {
    { '1', "Market" },
    { '2', "Limit" },
    { 'P', "Pegged" },
    { 0, NULL },
};

static const value_string boeTimeInForceStrings[] = {
    { '0', "Day" },
    { '1', "GTC (treated as Day)" },
    { '2', "At the Open" },
    { '3', "IOC (Immediate or Cancel)" },
    { '5', "GTX (Expires at end of day, US) or Market on Close (Europe)" },
    { '6', "GTD (Good until date)" },
    { '7', "At the Close" },
    { 'B', "Limit on Close" },
    { 'R', "RHO (Regular Hours Only)" },
    { 0, NULL },
};
static const value_string boeIdSourceStrings[] = {
    { '2', "SEDOL" },
    { '4', "ISIN" },
    { '5', "RIC" },
    { 0, NULL },
};
static const value_string boeCapacityStrings[] = {
    { 'A', "Agency" },
    { 'P', "Principal" },
    { 'R', "Riskless" },
    { 'C', "Customer" },
    { 'M', "Market Maker" },
    { 'F', "Firm" },
    { 0, NULL },
};

static const value_string boeCrossFlagStrings[] = {
    { 'F', "Match Only at Participant Level" },
    { 'M', "Match Only at Trading Firm Level" },
    { 0, NULL },
};

static const value_string boeDisplayIndicatorStrings[] = {
    { 'X', "Displayed" },
    { 'I', "Invisible" },
    { 'V', "Default" },
    { 'S', "Display Price Sliding" },
    { 'L', "Display Price Sliding Reject on Cross" },
    { 'R', "Reject" },
    { 'N', "No Rescrape at Limit" },
    { 0, NULL },
};

static const value_string boePutOrCallStrings[] = {
    { '0', "Put" },
    { '1', "Call" },
    { 0, NULL },
};

static const value_string boeOpenCloseStrings[] = {
    { 'O', "Open" },
    { 'C', "Close" },
    { 0, NULL },
};

static const value_string boeBaseLiquidityIndicatorStrings[] = {
    { 'A', "Added" },
    { 'R', "Removed" },
    { 'X', "Routed" },
    { 'C', "Auction" },
    { 'W', "Wait" },
};

static const value_string boeLocateReqdStrings[] = {
    { 'N', "Client Affirms Ability to Borrow" },
    { 'Y', "Client Does Not Affirm Ability to Borrow" },
};

static const value_string boeCancelOrigOnRejectStrings[] = {
    { 'N', "Leave Original Order Alone" },
    { 'Y', "Cancel Original Order if Modification Fails" },
};

static const value_string boeOrderRejectReasonStrings[] = {
    { 'A', "Admin" },
    { 'D', "Duplicate ClOrdID" },
    { 'H', "Halted" },
    { 'I', "Incorrect Data Center" },
    { 'K', "Order Rate Threshold Exceeded" },
    { 'L', "Price Exceeds Cross Range" },
    { 'N', "Ran Out of Liquidity to Execute Against" },
    { 'O', "ClOrdID Doesn't Match a Known Order" },
    { 'P', "Can't Modify an Order That is Pending Fill" },
    { 'Q', "Waiting for First Trade" },
    { 'R', "Routing Unavailable" },
    { 'U', "User Requested" },
    { 'V', "Would Wash" },
    { 'W', "Add Liquidity Only Order Would Remove" },
    { 'X', "Order Expired" },
    { 'Y', "Symbol Not Supported" },
    { 'Z', "Unforeseen Reason" },
    { 'm', "Market Access Risk Limit Exceeded" },
    { 'o', "Max Open Order Count Exceeded" },
    { 'r', "Reserve Reload" },
    { 'y', "Order Received by BATS During Replay" },
    { 0x00, "No Reject Reason" },
};

static const value_string boeModifyRejectReasonStrings[] = {
    { 'A', "Admin" },
    { 'D', "Duplicate ClOrdID" },
    { 'H', "Halted" },
    { 'I', "Incorrect Data Center" },
    { 'K', "Order Rate Threshold Exceeded" },
    { 'L', "Price Exceeds Cross Range" },
    { 'N', "Ran Out of Liquidity to Execute Against" },
    { 'O', "ClOrdID Doesn't Match a Known Order" },
    { 'P', "Can't Modify an Order That is Pending Fill" },
    { 'Q', "Waiting for First Trade" },
    { 'R', "Routing Unavailable" },
    { 'U', "User Requested" },
    { 'V', "Would Wash" },
    { 'W', "Add Liquidity Only Order Would Remove" },
    { 'X', "Order Expired" },
    { 'Y', "Symbol Not Supported" },
    { 'Z', "Unforeseen Reason" },
    { 'r', "Reserve Reload" },
    { 'y', "Order Received by BATS During Replay" },
};

static const value_string boeRestatementReasonStrings[] = {
    { 'R', "Reroute" },
    { 'A', "Entering Trading at Last Phase" },
    { 'X', "Locked in Cross" },
    { 'W', "Wash" },
    { 'L', "Reload" },
};

static const value_string boeSubLiquidityIndicatorStrings[] = {
    { '\0', "No Additional Information" },
    { 'D',  "BATS Dark Pool Execution" },
    { 'M',  "BATS Dark Self Cross Execution" },
    { 'T',  "Removed Liquidty From BATS Dark Pool by IOC Order" },
    { 'I',  "Trade Added Hidden Liquidity That Was Price Improved" },
    { 'H',  "Trade Added Hidden Liquidity" },
    { 'S',  "Execution from Order that set the NBBO" },
};

static const value_string boeCancelRejectReasonStrings[] = {
    { 'A', "Admin" },
    { 'I', "Incorrect Data Center" },
    { 'J', "Too Late to Cancel" },
    { 'P', "Can't Modify an Order that is Pending Fill" },
    { 'O', "ClOrdID Doesn't Match a Known Order" },
    { 'b', "Broker Option" },
    { 'y', "Cancel Received by BATS During Replay" },
};

typedef enum bit_formatting_type_ {
    bft_short_price,
    bft_long_price,
    bft_base36,
    bft_default,
} bit_formatting_type;

typedef struct bit_type_definition_ {
    const gchar *name;
    int *hfindex;
    gint length;
    bit_formatting_type type;
} bit_type_definition;

static bit_type_definition return_bits_1[] = {
    { "Side",                   &hf_batsboe_side,                     1,  bft_default },
    { "PegDifference",          &hf_batsboe_peg_difference,           8,  bft_default },
    { "Price",                  &hf_batsboe_price,                    8,  bft_long_price },
    { "ExecInst",               &hf_batsboe_exec_inst,                1,  bft_default },
    { "OrdType",                &hf_batsboe_ord_type,                 1,  bft_default },
    { "TimeInForce",            &hf_batsboe_time_in_force,            1,  bft_default },
    { "MinQty",                 &hf_batsboe_min_qty,                  4,  bft_default },
    { "MaxRemovePct",           &hf_batsboe_max_remove_pct,           1,  bft_default },
};

static bit_type_definition return_bits_2[] = {
    { "Symbol",                 &hf_batsboe_symbol,                   8,  bft_default },
    { "SymbolSfx",              &hf_batsboe_symbol_sfx,               8,  bft_default },
    { "Currency",               &hf_batsboe_currency,                 3,  bft_default },
    { "IDSource",               &hf_batsboe_idsource,                 1,  bft_default },
    { "SecurityID",             &hf_batsboe_security_id,              16, bft_default },
    { "SecurityExchange",       &hf_batsboe_security_exchange,        4,  bft_default },
    { "Capacity",               &hf_batsboe_capacity,                 1,  bft_default },
    { "CrossFlag",              &hf_batsboe_cross_flag,               1,  bft_default },
};

static bit_type_definition return_bits_3[] = {
    { "Account",                &hf_batsboe_account,                  16, bft_default },
    { "ClearingFirm",           &hf_batsboe_clearing_firm,            4,  bft_default },
    { "ClearingAccount",        &hf_batsboe_clearing_account,         4,  bft_default },
    { "DisplayIndicator",       &hf_batsboe_display_indicator,        1,  bft_default },
    { "MaxFloor",               &hf_batsboe_max_floor,                4,  bft_default },
    { "DiscretionAmount",       &hf_batsboe_discretion_amount,        2,  bft_default },
    { "OrderQty",               &hf_batsboe_order_qty,                4,  bft_default },
    { "PreventMatch",           &hf_batsboe_prevent_match,            3,  bft_default },
};

static bit_type_definition return_bits_4[] = {
    { "MaturityDate",           &hf_batsboe_maturity_date,            4,  bft_default },
    { "StrikePrice",            &hf_batsboe_strike_price,             8,  bft_long_price },
    { "PutOrCall",              &hf_batsboe_put_or_call,              1,  bft_default },
    { "OpenClose",              &hf_batsboe_open_close,               1,  bft_default },
    { "ClOrdIDBatch",           &hf_batsboe_cl_ord_id_batch,          20, bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition return_bits_5[] = {
    { "OrigClOrdID",            &hf_batsboe_orig_cl_ord_id,           20, bft_default },
    { "LeavesQty",              &hf_batsboe_leaves_qty,               4,  bft_default },
    { "LastShares",             &hf_batsboe_last_shares,              4,  bft_default },
    { "LastPx",                 &hf_batsboe_last_px,                  8,  bft_long_price },
    { "DisplayPrice",           &hf_batsboe_display_price,            8,  bft_long_price },
    { "WorkingPrice",           &hf_batsboe_working_price,            8,  bft_long_price },
    { "BaseLiquidityIndicator", &hf_batsboe_base_liquidity_indicator, 1,  bft_default },
    { "ExpireTime",             &hf_batsboe_expire_time,              8,  bft_default },
};

static bit_type_definition return_bits_6[] = {
    { "SecondaryOrderID",       &hf_batsboe_secondary_order_id,       8,  bft_base36 },
    { "CCP",                    &hf_batsboe_ccp,                      4,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "BulkOrderIds",           &hf_batsboe_bulk_order_ids,           8,  bft_base36 },
    { "BulkRejectReasons",      &hf_batsboe_bulk_reject_reasons,      1,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition return_bits_7[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition return_bits_8[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition *all_return_bits[] = {
    return_bits_1, return_bits_2, return_bits_3, return_bits_4, return_bits_5, return_bits_6, return_bits_7, return_bits_8, NULL
};

static bit_type_definition new_order_bits_1[] = {
    { "ClearingFirm",           &hf_batsboe_clearing_firm,            4,  bft_default },
    { "ClearingAccount",        &hf_batsboe_clearing_account,         4,  bft_default },
    { "Price",                  &hf_batsboe_price,                    8,  bft_long_price },
    { "ExecInst",               &hf_batsboe_exec_inst,                1,  bft_default },
    { "OrdType",                &hf_batsboe_ord_type,                 1,  bft_default },
    { "TimeInForce",            &hf_batsboe_time_in_force,            1,  bft_default },
    { "MinQty",                 &hf_batsboe_min_qty,                  4,  bft_default },
    { "MaxFloor",               &hf_batsboe_max_floor,                4,  bft_default },
};

static bit_type_definition new_order_bits_2[] = {
    { "Symbol",                 &hf_batsboe_symbol,                   8,  bft_default },
    { "SymbolSfx",              &hf_batsboe_symbol_sfx,               8,  bft_default },
    { "Currency",               &hf_batsboe_currency,                 3,  bft_default },
    { "IDSource",               &hf_batsboe_idsource,                 1,  bft_default },
    { "SecurityID",             &hf_batsboe_security_id,              16, bft_default },
    { "SecurityExchange",       &hf_batsboe_security_exchange,        4,  bft_default },
    { "Capacity",               &hf_batsboe_capacity,                 1,  bft_default },
    { "RoutingInst",            &hf_batsboe_routing_inst,             4,  bft_default },
};

static bit_type_definition new_order_bits_3[] = {
    { "Account",                &hf_batsboe_account,                  16, bft_default },
    { "DisplayIndicator",       &hf_batsboe_display_indicator,        1,  bft_default },
    { "MaxRemovePct",           &hf_batsboe_max_remove_pct,           1,  bft_default },
    { "DiscretionAmount",       &hf_batsboe_discretion_amount,        2,  bft_default },
    { "PegDifference",          &hf_batsboe_peg_difference,           8,  bft_default },
    { "PreventMatch",           &hf_batsboe_prevent_match,            3,  bft_default },
    { "LocateReqd",             &hf_batsboe_locate_reqd,              1,  bft_default },
    { "ExpireTime",             &hf_batsboe_expire_time,              8,  bft_default },
};

static bit_type_definition new_order_bits_4[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "RiskReset",              &hf_batsboe_risk_reset,               8,  bft_default },
    { "OpenClose",              &hf_batsboe_open_close,               1,  bft_default },
    { "CMTANumber",             &hf_batsboe_cmta_number,              4,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition new_order_bits_5[] = {
    { "CrossFlag",              &hf_batsboe_cross_flag,               1,  bft_default },
    { "AttributedQuote",        &hf_batsboe_attributed_quote,         1,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition new_order_bits_6[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition *new_order_bits[] = {
    new_order_bits_1, new_order_bits_2, new_order_bits_3, new_order_bits_4, new_order_bits_5, new_order_bits_6, NULL
};

static bit_type_definition bulk_order_bits_1[] = {
    { "ClearingFirm",           &hf_batsboe_clearing_firm,            4,  bft_default },
    { "ClearingAccount",        &hf_batsboe_clearing_account,         4,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "ExecInst",               &hf_batsboe_exec_inst,                1,  bft_default },
    { "OrdType",                &hf_batsboe_ord_type,                 1,  bft_default },
    { "TimeInForce",            &hf_batsboe_time_in_force,            1,  bft_default },
    { "MinQty",                 &hf_batsboe_min_qty,                  4,  bft_default },
    { "MaxFloor",               &hf_batsboe_max_floor,                4,  bft_default },
};

static bit_type_definition bulk_order_bits_2[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "Capacity",               &hf_batsboe_capacity,                 1,  bft_default },
    { "RoutingInst",            &hf_batsboe_routing_inst,             4,  bft_default },
};

static bit_type_definition bulk_order_bits_3[] = {
    { "Account",                &hf_batsboe_account,                  16, bft_default },
    { "DisplayIndicator",       &hf_batsboe_display_indicator,        1,  bft_default },
    { "MaxRemovePct",           &hf_batsboe_max_remove_pct,           1,  bft_default },
    { "DiscretionAmount",       &hf_batsboe_discretion_amount,        2,  bft_default },
    { "PegDifference",          &hf_batsboe_peg_difference,           8,  bft_default },
    { "PreventMatch",           &hf_batsboe_prevent_match,            3,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "ExpireTime",             &hf_batsboe_expire_time,              8,  bft_default },
};

static bit_type_definition bulk_order_bits_4[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "RiskReset",              &hf_batsboe_risk_reset,               8,  bft_default },
    { "OpenClose",              &hf_batsboe_open_close,               1,  bft_default },
    { "CMTANumber",             &hf_batsboe_cmta_number,              4,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition bulk_order_bits_5[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "AttributedQuote",        &hf_batsboe_attributed_quote,         1,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition bulk_order_bits_6[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition *bulk_order_bits[] = {
    bulk_order_bits_1, bulk_order_bits_2, bulk_order_bits_3, bulk_order_bits_4, bulk_order_bits_5, bulk_order_bits_6, NULL
};

static bit_type_definition bulk_order_group_bits_1[] = {
    { "BidShortPrice",          &hf_batsboe_bid_short_price,          4,  bft_short_price },
    { "BidOrderQty",            &hf_batsboe_bid_order_qty,            4,  bft_default },
    { "BidDiscretionAmount",    &hf_batsboe_bid_discretion_amount,    2,  bft_default },
    { "BidOpenClose",           &hf_batsboe_bid_open_close,           1,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition bulk_order_group_bits_2[] = {
    { "AskShortPrice",          &hf_batsboe_ask_short_price,          4,  bft_short_price },
    { "AskOrderQty",            &hf_batsboe_ask_order_qty,            4,  bft_default },
    { "AskDiscretionAmount",    &hf_batsboe_ask_discretion_amount,    2,  bft_default },
    { "AskOpenClose",           &hf_batsboe_ask_open_close,           1,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition *bulk_order_group_bits[] = {
    bulk_order_group_bits_1, bulk_order_group_bits_2, NULL
};

static bit_type_definition cancel_order_bits_1[] = {
    { "ClearingFirm",           &hf_batsboe_clearing_firm,            4,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition cancel_order_bits_2[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition *cancel_order_bits[] = {
    cancel_order_bits_1, cancel_order_bits_2, NULL
};

static bit_type_definition modify_order_bits_1[] = {
    { "ClearingFirm",           &hf_batsboe_clearing_firm,            4,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "OrderQty",               &hf_batsboe_order_qty,                4,  bft_default },
    { "Price",                  &hf_batsboe_price,                    8,  bft_long_price },
    { "OrdType",                &hf_batsboe_ord_type,                 1,  bft_default },
    { "CancelOrigOnReject",     &hf_batsboe_cancel_orig_on_reject,    1,  bft_default },
    { "ExecInst",               &hf_batsboe_exec_inst,                1,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition modify_order_bits_2[] = {
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
    { "<Reserved>",             0,                                    0,  bft_default },
};

static bit_type_definition *modify_order_bits[] = {
    modify_order_bits_1, modify_order_bits_2, NULL
};

#endif
