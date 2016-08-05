/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file s7 application layer detector and parser for learning and
 * s7 pruposes.
 *
 * This s7 implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-s7.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define S7_DEFAULT_PORT "7"

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define S7_MIN_FRAME_LEN 1

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert s7 any any -> any any (msg:"SURICATA s7 empty message"; \
 *    app-layer-event:s7.empty_message; sid:X; rev:Y;)
 */
enum {
    S7_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap s7_decoder_event_table[] = {
    {"EMPTY_MESSAGE", S7_DECODER_EVENT_EMPTY_MESSAGE},
};

static s7Transaction *s7TxAlloc(s7State *echo)
{
    s7Transaction *tx = SCCalloc(1, sizeof(s7Transaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}

static void s7TxFree(void *tx)
{
    s7Transaction *s7tx = tx;

    if (s7tx->request_buffer != NULL) {
        SCFree(s7tx->request_buffer);
    }

    if (s7tx->response_buffer != NULL) {
        SCFree(s7tx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&s7tx->decoder_events);

    SCFree(tx);
}

static void *s7StateAlloc(void)
{
    SCLogNotice("Allocating s7 state.");
    s7State *state = SCCalloc(1, sizeof(s7State));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void s7StateFree(void *state)
{
    s7State *s7_state = state;
    s7Transaction *tx;
    SCLogNotice("Freeing s7 state.");
    while ((tx = TAILQ_FIRST(&s7_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&s7_state->tx_list, tx, next);
        s7TxFree(tx);
    }
    SCFree(s7_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the s7State object.
 * \param tx_id the transaction ID to free.
 */
static void s7StateTxFree(void *state, uint64_t tx_id)
{
    s7State *echo = state;
    s7Transaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        s7TxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int s7StateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, s7_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "s7 enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *s7GetEvents(void *state, uint64_t tx_id)
{
    s7State *s7_state = state;
    s7Transaction *tx;

    TAILQ_FOREACH(tx, &s7_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int s7HasEvents(void *state)
{
    s7State *echo = state;
    return echo->events;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_S7 if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto s7ProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    /* Very simple test - if there is input, this is echo. */
    if (input_len >= S7_MIN_FRAME_LEN) {
        SCLogNotice("Detected as ALPROTO_S7.");
        return ALPROTO_S7;
    }

    SCLogNotice("Protocol not detected as ALPROTO_S7.");
    return ALPROTO_UNKNOWN;
}

static int s7ParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    s7State *echo = state;

    SCLogNotice("Parsing echo request: len=%"PRIu32, input_len);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */

    /* Also, if this protocol may have a "protocol data unit" span
     * multiple chunks of data, which is always a possibility with
     * TCP, you may need to do some buffering here.
     *
     * For the sake of simplicity, buffering is left out here, but
     * even for an echo protocol we may want to buffer until a new
     * line is seen, assuming its text based.
     */

    /* Allocate a transaction.
     *
     * But note that if a "protocol data unit" is not received in one
     * chunk of data, and the buffering is done on the transaction, we
     * may need to look for the transaction that this newly recieved
     * data belongs to.
     */
    s7Transaction *tx = s7TxAlloc(echo);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new s7 tx.");
        goto end;
    }
    SCLogNotice("Allocated s7 tx %"PRIu64".", tx->tx_id);
    
    /* Make a copy of the request. */
    tx->request_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->request_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->request_buffer, input, input_len);
    tx->request_buffer_len = input_len;

    /* Here we check for an empty message and create an app-layer
     * event. */
    if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
        (input_len == 2 && tx->request_buffer[0] == '\r')) {
        SCLogNotice("Creating event for empty message.");
        AppLayerDecoderEventsSetEventRaw(&tx->decoder_events,
            S7_DECODER_EVENT_EMPTY_MESSAGE);
        echo->events++;
    }

end:    
    return 0;
}

static int s7ParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    s7State *echo = state;
    s7Transaction *tx = NULL, *ttx;;

    SCLogNotice("Parsing s7 response.");

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * s7State object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &echo->tx_list, next) {
        tx = ttx;
    }
    
    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on echo state %p.",
            echo);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on echo state %p.",
        tx->tx_id, echo);

    /* If the protocol requires multiple chunks of data to complete, you may
     * run into the case where you have existing response data.
     *
     * In this case, we just log that there is existing data and free it. But
     * you might want to realloc the buffer and append the data.
     */
    if (tx->response_buffer != NULL) {
        SCLogNotice("WARNING: Transaction already has response data, "
            "existing data will be overwritten.");
        SCFree(tx->response_buffer);
    }

    /* Make a copy of the response. */
    tx->response_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->response_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->response_buffer, input, input_len);
    tx->response_buffer_len = input_len;

    /* Set the response_done flag for transaction state checking in
     * s7GetStateProgress(). */
    tx->response_done = 1;

end:
    return 0;
}

static uint64_t s7GetTxCnt(void *state)
{
    s7State *echo = state;
    SCLogNotice("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
}

static void *s7GetTx(void *state, uint64_t tx_id)
{
    s7State *echo = state;
    s7Transaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void s7SetTxLogged(void *state, void *vtx, uint32_t logger)
{
    s7Transaction *tx = (s7Transaction *)vtx;
    tx->logged |= logger;
}

static int s7GetTxLogged(void *state, void *vtx, uint32_t logger)
{
    s7Transaction *tx = (s7Transaction *)vtx;
    if (tx->logged & logger)
        return 1;

    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int s7GetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int s7GetStateProgress(void *tx, uint8_t direction)
{
    s7Transaction *echotx = tx;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", echotx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && echotx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For echo, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *s7GetTxDetectState(void *vtx)
{
    s7Transaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int s7SetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    s7Transaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void Registers7Parsers(void)
{
    char *proto_name = "s7";


    /* Check if s7 TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("s7 TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_S7, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, S7_DEFAULT_PORT,
                ALPROTO_S7, 0, S7_MIN_FRAME_LEN, STREAM_TOSERVER,
                s7ProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_S7, 0, S7_MIN_FRAME_LEN,
                    s7ProbingParser)) {
                SCLogNotice("No echo app-layer configuration, enabling echo"
                    " detection TCP detection on port %s.",
                    S7_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    S7_DEFAULT_PORT, ALPROTO_S7, 0,
                    S7_MIN_FRAME_LEN, STREAM_TOSERVER,
                    s7ProbingParser);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for s7.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogNotice("Registering s7 protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new s7 flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_S7,
            s7StateAlloc, s7StateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_S7,
            STREAM_TOSERVER, s7ParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_S7,
            STREAM_TOCLIENT, s7ParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_S7,
            s7StateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_S7,
            s7GetTxLogged, s7SetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_S7,
            s7GetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_S7,
            s7GetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_S7, s7GetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_S7,
            s7GetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_S7,
            s7HasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_S7,
            NULL, s7GetTxDetectState, s7SetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_S7,
            s7StateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_S7,
            s7GetEvents);
    }
    else {
        SCLogNotice("s7 protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_S7,
        s7ParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void s7ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
