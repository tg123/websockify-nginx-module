/**
  * Nginx Websockify Module
  * Embed websockify into Nginx
  * https://github.com/tg123/websockify-nginx-module
  *
  * WebSocket to TCP Protocol Bridge/Proxy
  * SEE ALSO: websockify https://github.com/kanaka/websockify
  *
  * Copyright (C) 2014 - 2015
  *
  * The MIT License (MIT)
  */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_sha1.h>

#include "websocket.h"

#define BUFFER_SIZE              (MAX_WEBSOCKET_FRAME_SIZE + MAX_WEBSOCKET_FRAME_HEADER_SIZE + WEBSOCKET_FRAME_MASK_SIZE)

#define BUFFER_FLUSH_TIMEOUT     20

#ifdef _MSC_VER
#define WEBSOCKIFY_FUNC __FUNCTION__
#else
#define WEBSOCKIFY_FUNC __func__
#endif

typedef struct ngx_http_websockify_loc_conf_s {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *websockify_lengths;
    ngx_array_t                   *websockify_values;
} ngx_http_websockify_loc_conf_t;

typedef enum {
    WEBSOCKIFY_ENCODING_PROTOCOL_UNSET = 0,
    WEBSOCKIFY_ENCODING_PROTOCOL_BASE64,
    WEBSOCKIFY_ENCODING_PROTOCOL_BINARY
} websockify_encoding_protocol_e;

typedef struct ngx_http_websockify_request_ctx_s {
    ngx_http_request_t                *request;
    ngx_flag_t                         need_cleanup_fake_recv_buff;
    ngx_flag_t                         closed;
    websockify_encoding_protocol_e     encoding_protocol;

    ngx_buf_t                         *encode_send_buf;
    ngx_buf_t                         *decode_send_buf;

    ngx_event_t                        flush_all_ev;

    ngx_send_pt                        original_ngx_downstream_send;
    ngx_send_pt                        original_ngx_upstream_send;

    ngx_recv_pt                        original_ngx_upstream_recv;

} ngx_http_websockify_ctx_t ;


ngx_module_t ngx_http_websockify_module;

static ngx_int_t ngx_http_websockify_handler(ngx_http_request_t *r);
static char *ngx_http_websockify(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);

static void *ngx_http_websockify_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_websockify_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);

static ngx_int_t ngx_http_websockify_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_websockify_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_websockify_process_header(ngx_http_request_t *r);
static void ngx_http_websockify_abort_request(ngx_http_request_t *r);
static void ngx_http_websockify_finalize_request(ngx_http_request_t *r,
        ngx_int_t rc);


static void ngx_http_websockify_flush_all(ngx_event_t *ev);

static ssize_t ngx_http_websockify_send(ngx_connection_t *c, ngx_buf_t *b,
                                        ngx_send_pt send);

static ngx_inline ssize_t ngx_http_websockify_flush_downstream(
    ngx_http_websockify_ctx_t *ctx);
static ngx_inline ssize_t ngx_http_websockify_flush_upstream(
    ngx_http_websockify_ctx_t *ctx);

static ngx_inline size_t ngx_http_websockify_freesize(ngx_buf_t *b,
        size_t size);

static ssize_t ngx_http_websockify_send_downstream_with_encode(
    ngx_connection_t *c,
    u_char *buf, const size_t size);

static ssize_t ngx_http_websockify_send_downstream_frame(
    ngx_http_websockify_ctx_t *ctx, u_char opcode, u_char *payload, size_t size);

static ssize_t ngx_http_websockify_send_upstream_with_decode(
    ngx_connection_t *c,
    u_char *buf, const size_t size);

static ssize_t ngx_http_websockify_empty_recv(ngx_connection_t *c, u_char *buf,
        size_t size);


static ngx_inline size_t ngx_http_websockify_freesize(ngx_buf_t *b, size_t size)
{

    size_t    free_size;

    free_size = b->end - b->last;

    if (free_size >= size) {
        return free_size;
    }

    return 0;
}

static ngx_inline ssize_t
ngx_http_websockify_flush_downstream(ngx_http_websockify_ctx_t *ctx)
{
    ngx_http_request_t        *r;
    r = ctx->request;

    if ( r->connection ) {
        return ngx_http_websockify_send(r->connection, ctx->encode_send_buf,
                                        ctx->original_ngx_downstream_send);
    }

    return NGX_ERROR;
}

static ngx_inline ssize_t
ngx_http_websockify_flush_upstream(ngx_http_websockify_ctx_t *ctx)
{
    ngx_http_request_t        *r;
    r = ctx->request;

    if ( r->upstream->peer.connection ) {
        return ngx_http_websockify_send(r->upstream->peer.connection,
                                        ctx->decode_send_buf, ctx->original_ngx_upstream_send);
    }

    return NGX_ERROR;
}

static void
ngx_http_websockify_flush_all(ngx_event_t *ev)
{
    ngx_http_websockify_ctx_t *ctx;

    ctx = ev->data;

    ngx_http_websockify_flush_downstream(ctx);
    ngx_http_websockify_flush_upstream(ctx);
}

static ssize_t
ngx_http_websockify_send(ngx_connection_t *c, ngx_buf_t *b,
                         ngx_send_pt send)
{
    ngx_http_websockify_ctx_t       *ctx;
    ngx_http_request_t              *r;
    ssize_t                         n;

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);


    if (b->last == b->pos) {
        return 0;
    }

    for (;;) {
        n = send(c, b->pos, b->last - b->pos);

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: sent buffer : %d / %d",
                       WEBSOCKIFY_FUNC, n, b->last - b->pos);

        if (n > 0) {
            b->pos += n;

            if (b->pos == b->last) {
                b->pos  = b->start;
                b->last = b->start;
            }
        }

        if (n == NGX_AGAIN) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: add timer", WEBSOCKIFY_FUNC);
            ngx_add_timer(&(ctx->flush_all_ev), BUFFER_FLUSH_TIMEOUT);
        }

        if ( (n <= 0) || (b->pos == b->last) ) {
            break;
        }
    }

    return n;
}

static ssize_t
ngx_http_websockify_send_downstream_frame(ngx_http_websockify_ctx_t *ctx,
        u_char opcode, u_char *payload, size_t size)
{
    ngx_buf_t          *b;
    size_t              header_length;


    if (ctx->closed) {
        return websocket_server_encoded_length(size);
    }

    if (ngx_http_websockify_flush_downstream(ctx) == NGX_ERROR ) {
        return NGX_ERROR;
    }

    header_length  = websocket_server_encoded_header_length(size);

    b = ctx->encode_send_buf;

    if ( !ngx_http_websockify_freesize(b, (header_length + size))) {
        return NGX_AGAIN;
    }

    websocket_server_write_frame_header(b->last, opcode, size);

    if (size > 0) {
        ngx_memcpy(b->last + header_length, payload, size);
    }

    if (ngx_http_websockify_flush_downstream(ctx) == NGX_ERROR ) {
        return NGX_ERROR;
    }

    b->last += header_length + size;

    return header_length + size;
}

static ssize_t
ngx_http_websockify_send_downstream_with_encode(ngx_connection_t *c,
        u_char *buf,
        const size_t size)
{
    ngx_http_websockify_ctx_t       *ctx;
    ngx_buf_t                       *b;
    ngx_http_request_t              *r;
    size_t                           payload_length;
    size_t                           header_length;

    size_t                           free_size;
    size_t                           consumed_size = 0;


    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: sending data...[%d]",
                   WEBSOCKIFY_FUNC, size);

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    // should not send anything to client
    if (ctx->closed) {
        return size;
    }

    // make more buf
    if (ngx_http_websockify_flush_downstream(ctx) == NGX_ERROR ) {
        return NGX_ERROR;
    }

    b = ctx->encode_send_buf;
    free_size = ngx_http_websockify_freesize(b, MIN_SERVER_FRAME_SIZE);

    if ( !free_size ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "%s: no enough buffer, try again... ", WEBSOCKIFY_FUNC);
        return NGX_AGAIN;
    }

    free_size = ngx_min(free_size,
                        MAX_WEBSOCKET_FRAME_SIZE + MAX_WEBSOCKET_FRAME_HEADER_SIZE);

    // TODO clean up code, UGLY
    if (ctx->encoding_protocol == WEBSOCKIFY_ENCODING_PROTOCOL_BASE64) {

        // inverse of ngx_base64_encoded_length.
        consumed_size  = ngx_min( (free_size - MAX_WEBSOCKET_FRAME_HEADER_SIZE) / 4 * 3
                                  - 2, size);

        payload_length = ngx_base64_encoded_length(consumed_size);
        header_length  = websocket_server_encoded_header_length(payload_length);

        websocket_server_write_frame_header(b->last, WEBSOCKET_OPCODE_TEXT,
                                            payload_length);

        // base64 encode
        ngx_str_t src;
        ngx_str_t dst;

        src.data = buf;
        src.len  = consumed_size;

        dst.data = b->last + header_length;

        ngx_encode_base64(&dst, &src);

    } else {
        consumed_size = ngx_min( free_size - MAX_WEBSOCKET_FRAME_HEADER_SIZE, size);

        payload_length = consumed_size;
        header_length  = websocket_server_encoded_header_length(payload_length);

        websocket_server_write_frame_header(b->last, WEBSOCKET_OPCODE_BINARY,
                                            payload_length);

        ngx_memcpy(b->last + header_length, buf, consumed_size);
    }

    b->last += header_length + payload_length; // push encoded data into buffer

    if (ngx_http_websockify_flush_downstream(ctx) == NGX_ERROR ) {
        return NGX_ERROR;
    }

    return (ssize_t)consumed_size;
}

static ssize_t
ngx_http_websockify_send_upstream_with_decode(ngx_connection_t *c, u_char *buf,
        const size_t size)
{
    ngx_http_websockify_ctx_t       *ctx;
    ngx_buf_t                       *b;
    ngx_http_request_t              *r;
    websocket_frame_t                frame;

    ssize_t                          header_length;
    size_t                           used_buf_size;
    ssize_t                          reply;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: [%d]", WEBSOCKIFY_FUNC,
                   size);

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    b = ctx->decode_send_buf;

    // make more buf
    if (ngx_http_websockify_flush_upstream(ctx) == NGX_ERROR ) {
        return NGX_ERROR;
    }

    header_length = websocket_server_decode_next_frame(&frame, buf, size);

    if (header_length == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "%s: decoding websocket frame > 65535 is not supported!",
                      WEBSOCKIFY_FUNC);
        return NGX_ERROR;
    }

    if (header_length == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    used_buf_size = 0;

    switch (frame.opcode) {
    case WEBSOCKET_OPCODE_CONTINUATION:
    case WEBSOCKET_OPCODE_PONG:
        // do nothing
        break;

    case WEBSOCKET_OPCODE_TEXT:
    case WEBSOCKET_OPCODE_BINARY:
        // FIXME when client send a frame > buffer_size can not hold
        // current frame remaining data, the connection will hang, should log an error

        if (ctx->encoding_protocol == WEBSOCKIFY_ENCODING_PROTOCOL_BASE64) {
            ngx_str_t src;
            ngx_str_t dst;

            // base64 decode the data
            if ( !ngx_http_websockify_freesize(b,
                                               ngx_base64_decoded_length(frame.payload_length)) ) {
                return NGX_AGAIN;
            }

            websocket_server_decode_unmask_payload(&frame);

            src.data = frame.payload;
            src.len =  frame.payload_length;

            dst.data = b->last;

            if ( ngx_decode_base64(&dst, &src) != NGX_OK ) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "%s: decode websocket base64 frame payload error!", WEBSOCKIFY_FUNC);
                return NGX_ERROR;
            }

            used_buf_size = dst.len;

        } else {

            if ( !ngx_http_websockify_freesize(b, frame.payload_length) ) {
                return NGX_AGAIN;
            }

            websocket_server_decode_unmask_payload(&frame);

            ngx_memcpy(b->last, frame.payload, frame.payload_length);

            used_buf_size = frame.payload_length;
        }

        break;

    case WEBSOCKET_OPCODE_CLOSE:
        // TODO testcases
        // TODO status code hardcoded (1000 = 03e8)
        // TODO connection should be closed
        reply = ngx_http_websockify_send_downstream_frame(ctx, WEBSOCKET_OPCODE_CLOSE,
                (u_char *)"\x03\xe8 Closed", 9);

        if (reply < 0) {
            return reply;
        }

        ctx->closed = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: CLOSE replied [%d]",
                       WEBSOCKIFY_FUNC,
                       size);

        break;

    case WEBSOCKET_OPCODE_PING:

        // TODO testcases

        if ( !ngx_http_websockify_freesize(ctx->encode_send_buf,
                                           websocket_server_encoded_length(frame.payload_length))) {
            return NGX_AGAIN;
        }

        websocket_server_decode_unmask_payload(&frame);

        reply = ngx_http_websockify_send_downstream_frame(ctx, WEBSOCKET_OPCODE_PONG,
                frame.payload, frame.payload_length);

        if (reply < 0) {
            return reply;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: PING replied [%d]",
                       WEBSOCKIFY_FUNC,
                       size);

        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "%s: unsupported opcode: [%d] ",
                      WEBSOCKIFY_FUNC, frame.opcode);
        break;
    }

    b->last += used_buf_size; // push decoded data into buffer

    if (ngx_http_websockify_flush_upstream(ctx) == NGX_ERROR ) {
        return NGX_ERROR;
    }

    return (ssize_t)(header_length + frame.payload_length);
}

static ngx_command_t ngx_http_websockify_commands[] = {
    {
        ngx_string("websockify_pass"),
        NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
        &ngx_http_websockify,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("websockify_buffer_size"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_websockify_loc_conf_t, upstream.buffer_size),
        NULL
    },

    {
        ngx_string("websockify_connect_timeout"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_websockify_loc_conf_t, upstream.connect_timeout),
        NULL
    },

    {
        ngx_string("websockify_send_timeout"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_websockify_loc_conf_t, upstream.send_timeout),
        NULL
    },

    {
        ngx_string("websockify_read_timeout"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_websockify_loc_conf_t, upstream.read_timeout),
        NULL
    },

    ngx_null_command
};


static void *
ngx_http_websockify_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_websockify_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_websockify_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    //conf->upstream.buffer_size = BUFFER_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    //conf->upstream.buffer_size = 0;
    //conf->upstream.busy_buffers_size = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    return conf;
}

static char *
ngx_http_websockify_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_websockify_loc_conf_t *prev = parent;
    ngx_http_websockify_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                             prev->upstream.local, NULL);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) BUFFER_SIZE);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                                 prev->upstream.next_upstream,
                                 (NGX_CONF_BITMASK_SET
                                  | NGX_HTTP_UPSTREAM_FT_ERROR
                                  | NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->websockify_lengths == NULL) {
        conf->websockify_lengths = prev->websockify_lengths;
        conf->websockify_values = prev->websockify_values;
    }
    if (conf->upstream.buffer_size == 0) {
        conf->upstream.buffer_size = BUFFER_SIZE;
    }

    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_websockify_module_ctx = {
    NULL,                       /* preconfiguration */
    NULL,                       /* postconfiguration */

    NULL,                       /* create main configuration */
    NULL,                       /* init main configuration */

    NULL,                       /* create server configuration */
    NULL,                       /* merge server configuration */

    ngx_http_websockify_create_loc_conf, /* create location configuration */
    ngx_http_websockify_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_websockify_module = {
    NGX_MODULE_V1,
    &ngx_http_websockify_module_ctx,    /* module context */
    ngx_http_websockify_commands,       /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_websockify_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_upstream_t             *u;
    ngx_http_websockify_loc_conf_t  *wlcf;
    ngx_http_websockify_ctx_t       *ctx;
    ngx_str_t                        var_pass;
    ngx_url_t                        url;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_websockify_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if ( wlcf->websockify_lengths ) { // parse from var

        if (ngx_http_script_run(r, &var_pass, wlcf->websockify_lengths->elts, 0,
                                wlcf->websockify_values->elts) == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
        if (u->resolved == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memzero(&url, sizeof(ngx_url_t));

        url.url.len = var_pass.len;
        url.url.data = var_pass.data;
        url.uri_part = 1;
        url.no_resolve = 1;

        if (ngx_parse_url(r->pool, &url) != NGX_OK) {
            if (url.err) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "%s in upstream \"%V\"", url.err, &url.url);
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        u->resolved->host = url.host;
        u->resolved->port = (in_port_t) (url.no_port ? 5900 : url.port);
        u->resolved->no_port = url.no_port;

    }

    u->schema.len = sizeof("websockify://") - 1;
    u->schema.data = (u_char *) "websockify://";

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;

    u->output.tag = (ngx_buf_tag_t) &ngx_http_websockify_module;

    u->conf = &wlcf->upstream;

    u->create_request = ngx_http_websockify_create_request;
    u->reinit_request = ngx_http_websockify_reinit_request;
    u->process_header = ngx_http_websockify_process_header;
    u->abort_request = ngx_http_websockify_abort_request;
    u->finalize_request = ngx_http_websockify_finalize_request;

    r->upstream = u;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_websockify_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->encode_send_buf = ngx_create_temp_buf(r->pool, u->conf->buffer_size);
    ctx->decode_send_buf = ngx_create_temp_buf(r->pool, u->conf->buffer_size);

    ctx->encoding_protocol = WEBSOCKIFY_ENCODING_PROTOCOL_UNSET;

    ctx->flush_all_ev.log     = r->connection->log;
    ctx->flush_all_ev.data    = ctx;
    ctx->flush_all_ev.handler = ngx_http_websockify_flush_all;

    ctx-> closed = 0;

    if (!ctx->encode_send_buf || !ctx->decode_send_buf) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_websockify_module);

    //ngx_http_upstream_init(r);
    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

static ngx_int_t
ngx_http_websockify_create_request(ngx_http_request_t *r)
{
    ngx_http_websockify_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    if ( ctx == NULL ) {
        return NGX_ERROR;
    }

    // tricky, let nginx call my reinit
    // do nothing to tcp connections
    r->upstream->request_sent = 1;

    return NGX_OK;
}

static ssize_t
ngx_http_websockify_empty_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_request_t              *r;
    ngx_http_websockify_ctx_t       *ctx;
    ssize_t                         n;

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    n = ctx->original_ngx_upstream_recv(c, buf, 1);
    c->recv = ctx->original_ngx_upstream_recv;

    // tricky, if n == NGX_ERROR upstream might not have connections now
    // return control to nginx and let nginx deal with it
    if (n == NGX_ERROR) {
        return NGX_AGAIN;
    }

    if (n == NGX_AGAIN) {
        ctx->need_cleanup_fake_recv_buff = 1;
        return 1;
    }

    ctx->need_cleanup_fake_recv_buff = 0;
    return n;
}

static ngx_int_t
ngx_http_websockify_reinit_request(ngx_http_request_t *r)
{
    ngx_http_upstream_t         *u;
    ngx_http_websockify_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    if (r->header_sent) {
        return NGX_OK;
    }

    u = r->upstream;
    // hack for empty reply tcp connection
    ctx->original_ngx_upstream_recv = u->peer.connection->recv;
    u->peer.connection->recv = ngx_http_websockify_empty_recv;

    u->read_event_handler(r, r->upstream);

    // this happens if some error occurs during read_event_handler
    if ( u->peer.connection == NULL ) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_websockify_process_header(ngx_http_request_t *r)
{
    ngx_http_websockify_ctx_t   *ctx;
    ngx_http_upstream_t         *u;

    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;
    ngx_sha1_t                   sha1;
    ngx_str_t                    ws_key = {0, NULL};

    ngx_flag_t                   accept_binary = 0;
    ngx_flag_t                   accept_base64 = 0;


    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "websockify : ngx_http_websockify_process_header");

    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    if ( ctx == NULL ) {
        return NGX_ERROR;
    }

    u = r->upstream;

    if (ctx->need_cleanup_fake_recv_buff) {
        u->buffer.last = u->buffer.start;
    }

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (ngx_strncasecmp(h[i].key.data, (u_char *) "Sec-WebSocket-Key",
                            h[i].key.len) == 0) {
            ngx_str_t src;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "websockify : found SEC_WEBSOCKET_KEY : %s", h[i].value.data);

            src.data = ngx_palloc(r->pool, 20 * sizeof(u_char));
            src.len = 20;

            if (src.data == NULL) {
                return NGX_ERROR;
            }

            ngx_sha1_init(&sha1);
            ngx_sha1_update(&sha1, h[i].value.data, h[i].value.len);
            ngx_sha1_update(&sha1, HYBI_GUID, 36);
            ngx_sha1_final(src.data, &sha1);

            ws_key.len = HYBI10_ACCEPTHDRLEN; //MAX ACCEPT
            ws_key.data = ngx_palloc(r->pool, HYBI10_ACCEPTHDRLEN);

            if ( ws_key.data == NULL) {
                return NGX_ERROR;
            }

            ngx_encode_base64(&ws_key, &src);

        } else if (ngx_strncasecmp(h[i].key.data, (u_char *) "Sec-WebSocket-Protocol",
                                   h[i].key.len) == 0) {

            if (ngx_strstrn(h[i].value.data, "base64", 6 - 1)) {
                accept_base64 = 1;
            }

            if (ngx_strstrn(h[i].value.data, "binary", 6 - 1)) {
                accept_binary = 1;
            }

        }
    }

    if ( ws_key.len > 0 && ( accept_base64 || accept_binary ) ) {

        u->headers_in.status_n = NGX_HTTP_SWITCHING_PROTOCOLS;
        ngx_str_set(&u->headers_in.status_line, "101 Switching Protocols");
        u->headers_in.content_length_n = -1;

        h = ngx_list_push(&r->headers_out.headers);
        h->hash = 1;
        ngx_str_set(&h->key, "Sec-WebSocket-Accept");
        h->value = ws_key;

        h = ngx_list_push(&r->headers_out.headers);
        h->hash = 1;
        ngx_str_set(&h->key, "Upgrade");
        ngx_str_set(&h->value, "websocket");

        h = ngx_list_push(&r->headers_out.headers);
        h->hash = 1;
        ngx_str_set(&h->key, "Sec-WebSocket-Protocol");

        if ( accept_binary ) {
            ngx_str_set(&h->value, "binary");
            ctx->encoding_protocol = WEBSOCKIFY_ENCODING_PROTOCOL_BINARY;
        } else {
            ngx_str_set(&h->value, "base64");
            ctx->encoding_protocol = WEBSOCKIFY_ENCODING_PROTOCOL_BASE64;
        }

        u->state->status = u->headers_in.status_n;
        u->upgrade = 1;

        if ( r->connection->send != ngx_http_websockify_send_downstream_with_encode ) {
            ctx->original_ngx_downstream_send = r->connection->send;
            r->connection->send = ngx_http_websockify_send_downstream_with_encode;
        }

        if ( r->upstream->peer.connection->send !=
             ngx_http_websockify_send_upstream_with_decode ) {
            ctx->original_ngx_upstream_send = r->upstream->peer.connection->send;
            r->upstream->peer.connection->send =
                ngx_http_websockify_send_upstream_with_decode;
        }



    } else {
        u->headers_in.status_n = NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static void
ngx_http_websockify_abort_request(ngx_http_request_t *r)
{
    return;
}

static void
ngx_http_websockify_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    return;
}

static char *
ngx_http_websockify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_websockify_loc_conf_t   *wlcf = conf;

    ngx_str_t                        *value, *url;
    ngx_url_t                         u;
    ngx_uint_t                        n;
    ngx_http_core_loc_conf_t         *clcf;
    ngx_http_script_compile_t         sc;

    if (wlcf->upstream.upstream || wlcf->websockify_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_websockify_handler;

    // TODO websockify://
    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &wlcf->websockify_lengths;
        sc.values = &wlcf->websockify_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    u.url.data = url->data;
    u.url.len = url->len;
    u.default_port = 5900;
    u.no_resolve = 1;

    wlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (wlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
