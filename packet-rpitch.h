#ifndef __PACKET_RPITCH_H__
#define __PACKET_RPITCH_H__

static const gint LOGIN_REQUEST_LEN  = 32;
static const gint LOGIN_RESPONSE_LEN = 7;
static const gint HEARTBEAT_LEN      = 6;
static const gint ADD_ORDER_LEN      = 47;
static const gint MODIFY_ORDER_LEN   = 34;
static const gint DELETE_ORDER_LEN   = 22;
static const gint SYMBOL_CLEAR_LEN   = 22;
static const gint ROOM_STATUS_LEN    = 23;

static const value_string rpitchMessageTypeStrings[] = {
    { 0xBF, "Login" },
    { 0xC0, "Login Response" },
    { 0xC1, "Heartbeat" },
    { 0xC2, "Add Order" },
    { 0xC3, "Modify Order" },
    { 0xC4, "Delete Order" },
    { 0xC5, "Symbol Clear" },
    { 0xC6, "Room Status" },
    { 0, NULL },
};

static const value_string rpitchLoginResponseStatusStrings[] = {
    { 0x00, "Login Accepted" },
    { 0x01, "Not Authorized" },
    { 0x02, "Session in Use" },
    { 0x03, "Invalid Session" },
    { 0, NULL },
};

static const value_string rpitchQuoteStatusStrings[] = {
    { 0x00, "Firm" },
    { 0x01, "Indicative" },
    { 0x02, "Suspended" },
    { 0, NULL },
};

#endif
