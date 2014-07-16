/**
  * Nginx Websockify Module
  * Embed websockify into Nginx
  * 
  * WebSocket to TCP Protocol Bridge/Proxy
  * SEE ALSO: websockify https://github.com/kanaka/websockify
  *
  * Copyright (C) Boshi Lian, Hao Chen
  * 
  * Copyright (C) 2014
  * 
  */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_sha1.h>

#define HYBI_GUID               "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define HYBI10_ACCEPTHDRLEN     29

#define BUFFER_SIZE             32768
#define SEND_MAX_BUFFER_SIZE    16384

static ngx_int_t ngx_http_websockify_handler(ngx_http_request_t *r);
static char *ngx_http_websockify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_websockify_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_websockify_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_websockify_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_websockify_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_websockify_process_header(ngx_http_request_t *r);
static void ngx_http_websockify_abort_request(ngx_http_request_t *r);
static void ngx_http_websockify_finalize_request(ngx_http_request_t *r, ngx_int_t rc);


static void ngx_http_websockify_buf_cleanup(ngx_event_t *ev);
static ssize_t ngx_http_websockify_send_buffer(ngx_connection_t *c, ngx_buf_t* b, ngx_send_pt send);
static ssize_t ngx_http_websockify_send_with_encode(ngx_connection_t *c, u_char *buf, size_t size);
static ssize_t ngx_http_websockify_send_with_decode(ngx_connection_t *c, u_char *buf, size_t size);


static ngx_send_pt original_ngx_send_with_encode;
static ngx_send_pt original_ngx_send_with_decode;

static ngx_recv_pt original_ngx_upstream_recv;

typedef struct ngx_http_websockify_loc_conf_s {
    ngx_http_upstream_conf_t       upstream; 
    size_t                         chunk_size;

    ngx_array_t                   *websockify_lengths;
    ngx_array_t                   *websockify_values;
} ngx_http_websockify_loc_conf_t;

typedef struct ngx_http_websockify_request_ctx_s {
    ngx_http_request_t        *request;
    ngx_str_t                  ws_key;
    ngx_flag_t                 header_processed;

    ngx_buf_t                 *encode_send_buf;
    ngx_buf_t                 *decode_send_buf;

    ngx_event_t                buf_cleanup_ev;
} ngx_http_websockify_ctx_t ;


ngx_module_t ngx_http_websockify_module;


// {{{ code from websockify.c 
static ssize_t 
ngx_http_websockify_encode_hybi(u_char *src, size_t srclength,
                u_char *target, size_t targsize, unsigned int opcode)
{
    size_t b64_sz;
    unsigned int payload_offset = 2;
    
    if ((int)srclength <= 0)
    {
        return 0;
    }

    //b64_sz = ngx_base64_encoded_length(srclength);
    b64_sz = srclength;

    target[0] = (char)((opcode & 0x0F) | 0x80);

    if (b64_sz <= 125) {
        target[1] = (char) b64_sz;
        payload_offset = 2;
    } else if ((b64_sz > 125) && (b64_sz < 65536)) {
        target[1] = (char) 126;
        *(u_short*)&(target[2]) = htons(b64_sz);
        payload_offset = 4;
    }
    // TODO return fail or trim

    #if 0
    ngx_str_t b64src;
    b64src.data = src;
    b64src.len  = srclength;

    ngx_str_t dst;
    dst.data = target + payload_offset;
    dst.len  = b64_sz;

    ngx_encode_base64(&dst, &b64src);
    #endif

    ngx_memcpy(target + payload_offset, src, srclength);

    return b64_sz + payload_offset;
}

static ssize_t 
ngx_http_websockify_decode_hybi(unsigned char *src, size_t srclength,
                u_char *target, size_t targsize, 
                unsigned int *opcode, unsigned int *left)
{
    unsigned char *frame, *mask, *payload, save_char/*, cntstr[4];*/;
    int masked = 0;
    int i = 0, len, framecount = 0;
    size_t remaining = 0;
    unsigned int target_offset = 0, hdr_length = 0, payload_length = 0;
    
    *left = srclength;
    frame = src;

    //printf("Deocde new frame\n");
    while (1) {
        // Need at least two bytes of the header
        // Find beginning of next frame. First time hdr_length, masked and
        // payload_length are zero
        frame += hdr_length + 4*masked + payload_length;
        //printf("frame[0..3]: 0x%x 0x%x 0x%x 0x%x (tot: %d)\n",
        //       (unsigned char) frame[0],
        //       (unsigned char) frame[1],
        //       (unsigned char) frame[2],
        //       (unsigned char) frame[3], srclength);

        if (frame > src + srclength) {
            //printf("Truncated frame from client, need %d more bytes\n", frame - (src + srclength) );
            break;
        }
        remaining = (src + srclength) - frame;
        if (remaining < 2) {
            //printf("Truncated frame header from client\n");
            break;
        }
        framecount ++;

        *opcode = frame[0] & 0x0f;
        masked = (frame[1] & 0x80) >> 7;

        if (*opcode == 0x8) {
            // client sent orderly close frame
            break;
        }

        payload_length = frame[1] & 0x7f;
        if (payload_length < 126) {
            hdr_length = 2;
            //frame += 2 * sizeof(char);
        } else if (payload_length == 126) {
            payload_length = (frame[2] << 8) + frame[3];
            hdr_length = 4;
        } else {
            //handler_emsg("Receiving frames larger than 65535 bytes not supported\n");
            return -1;
        }
        if ((hdr_length + 4*masked + payload_length) > remaining) {
            continue;
        }
        //printf("    payload_length: %u, raw remaining: %u\n", payload_length, remaining);
        payload = frame + hdr_length + 4*masked;

        if (*opcode != 1 && *opcode != 2) {
            //handler_msg("Ignoring non-data frame, opcode 0x%x\n", *opcode);
            continue;
        }

        if (payload_length == 0) {
            //handler_msg("Ignoring empty frame\n");
            continue;
        }

        if ((payload_length > 0) && (!masked)) {
            ///handler_emsg("Received unmasked payload from client\n");
            return -1;
        }

        // Terminate with a null for base64 decode
        save_char = payload[payload_length];
        payload[payload_length] = '\0';

        // unmask the data
        mask = payload - 4;
        for (i = 0; (unsigned int)i < payload_length; i++) {
            payload[i] ^= mask[i%4];
        }


        #if 0
        // base64 decode the data
        //len = b64_pton((const char*)payload, target+target_offset, targsize);
        if ( target_offset + ngx_base64_decoded_length(payload_length) > targsize ){
            break;
        }

        ngx_str_t b64src;
        b64src.data = payload;
        b64src.len = payload_length;

        ngx_str_t b64dst;
        b64dst.data = target + target_offset;

        if( ngx_decode_base64(&b64dst, &b64src) != NGX_OK ){
            return NGX_ERROR;
        }

        len = b64dst.len;
        #endif

        ngx_memcpy(target + target_offset, payload, payload_length);
        len = payload_length;

        // TODO clean up code
        // Restore the first character of the next frame
        payload[payload_length] = save_char;
        //if (len < 0) {
            //handler_emsg("Base64 decode error code %d", len);
        //    return len;
        //}
        target_offset += len;

        //printf("    len %d, raw %s\n", len, frame);
    }

    
    *left = remaining;
    return target_offset;
}

//}}}

static void  
ngx_http_websockify_buf_cleanup(ngx_event_t *ev)   
{  
    ngx_http_websockify_ctx_t *ctx;
    ngx_http_request_t        *r;

    ctx = ev->data;
    r = ctx->request;

    if ( r->connection ){
        ngx_http_websockify_send_buffer(r->connection, ctx->encode_send_buf, original_ngx_send_with_encode);
    }

    if ( r->upstream->peer.connection ) {
        ngx_http_websockify_send_buffer(r->upstream->peer.connection, ctx->decode_send_buf, original_ngx_send_with_decode);
    }

}  

static ssize_t
ngx_http_websockify_send_buffer(ngx_connection_t *c, ngx_buf_t* b, ngx_send_pt send)
{
    ngx_http_websockify_ctx_t       *ctx;
    ngx_http_request_t        *r;

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    ssize_t n;

    if (b->last == b->pos){
        return 0;
    }

    for(;;){
        n = send(c, b->pos, b->last - b->pos);

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: sent buffer : %d / %d", __func__, n, b->last - b->pos);

        if (n > 0) {
            b->pos += n;

            if (b->pos == b->last) {
                b->pos = b->start;
                b->last = b->start;
            }
        }

        if (n == NGX_AGAIN){
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: add timer", __func__);
            ngx_add_timer(&(ctx->buf_cleanup_ev), 20); // TODO hardcode
        } 

        if ( (n <= 0) || (b->pos == b->last) ) {
            break;
        }
    }

    return n;
}

static ssize_t 
ngx_http_websockify_send_with_encode(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_websockify_loc_conf_t  *wlcf;
    ngx_http_websockify_ctx_t       *ctx;
    ngx_buf_t                 *b;
    ngx_http_request_t        *r;
    ssize_t                    n;
    ssize_t                    payload;

    size_t                     free_size;
    size_t                     consumed_size = 0, chunk_size = 0; 


    ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: sending data...[%d]", __func__, size);

    r = c->data;
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_websockify_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    chunk_size = wlcf->chunk_size;
    if (chunk_size > 0 && size > chunk_size){
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: size is too large[%d], send part of it...[%d]", __func__, size, chunk_size);
        size = chunk_size;
    }


    b = ctx->encode_send_buf;

    if ( b->pos < b->last ){
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: old buff not clean...[%d]", __func__, b->last - b->pos);

        n = ngx_http_websockify_send_buffer(c, b, original_ngx_send_with_encode);
        if ( n == NGX_ERROR ){
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s: send buffer error! ", __func__);
            return NGX_ERROR;
        }
    }

    free_size = b->end - b->last;

    if (free_size <= 8) {  // no enough buffer at this time 4 header + 4 min base64 encode 1 char
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: no enough buffer, try again... ", __func__);
        return NGX_AGAIN;
    }

    consumed_size = ngx_min( (free_size - 4) / 4 * 3 - 4, size);

    payload = ngx_http_websockify_encode_hybi(buf, consumed_size, b->last , free_size , 2);

    // todo cleanup cant happen
    if (payload < 0){
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s: encode error! ", __func__);
        return NGX_ERROR;
    }

    b->last += payload; // push encoded data into buffer

    n = ngx_http_websockify_send_buffer(c, b, original_ngx_send_with_encode);
    if ( n == NGX_ERROR ){
        return NGX_ERROR;
    }
    
    return (ssize_t)consumed_size;

}

static ssize_t 
ngx_http_websockify_send_with_decode(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_websockify_loc_conf_t  *wlcf;
    ngx_http_websockify_ctx_t       *ctx;
    ngx_buf_t                 *b;
    ngx_http_request_t        *r;
    ssize_t                    n;

    size_t                     free_size;
    unsigned int               opcode = 0, left;
    ssize_t                    payload;
    size_t                     chunk_size;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: [%d]", __func__, size);


    r = c->data;
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_websockify_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    chunk_size = wlcf->chunk_size;

    if (chunk_size > 0 && size > chunk_size){
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: size is too large[%d], send part of it...[%d]", __func__, size, chunk_size);
        size = chunk_size;
    }
    

    b = ctx->decode_send_buf;

    if ( b-> pos < b->last ){
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: old buff not clean...[%d]", __func__, b->last - b->pos);

        n = ngx_http_websockify_send_buffer(c, b, original_ngx_send_with_decode);
        if ( n == NGX_ERROR ){
            return NGX_ERROR;
        }
    }

    free_size = b->end - b->last;

    if (free_size <= 10) {  
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s: no enough buffer, try again... ", __func__);
        return NGX_AGAIN;
    }
    

    payload = ngx_http_websockify_decode_hybi(buf, size, b->last , free_size, &opcode, &left);

    if ( opcode == 8){ // client closed
        // todo close upstream
        return size;
    }

    if (payload == 0) {
        return NGX_AGAIN;

    } else if (payload < 0){
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "%s: decode error! ", __func__);
        return NGX_ERROR;
    }

    b->last += payload; // push decoded data into buffer

    n = ngx_http_websockify_send_buffer(c, b, original_ngx_send_with_decode);
    if ( n == NGX_ERROR ){
        return NGX_ERROR;
    }

    return (ssize_t)(size - left);
}

static ngx_command_t ngx_http_websockify_commands[] = {
    { ngx_string("websockify_pass"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        &ngx_http_websockify,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    { ngx_string("websockify_buffer_size"),
          NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
          ngx_conf_set_size_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(ngx_http_websockify_loc_conf_t, upstream.buffer_size),
          NULL }, 
    { ngx_string("websockify_send_chunk_size"),
          NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
          ngx_conf_set_size_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(ngx_http_websockify_loc_conf_t, chunk_size),
          NULL }, 
    
    ngx_null_command
};


static void *
ngx_http_websockify_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_websockify_loc_conf_t * conf;

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


    conf->chunk_size = NGX_CONF_UNSET_SIZE;

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

    ngx_conf_merge_size_value(conf->chunk_size,
                              prev->chunk_size,
                              (size_t) SEND_MAX_BUFFER_SIZE);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->websockify_lengths == NULL) {
        conf->websockify_lengths = prev->websockify_lengths;
        conf->websockify_values = prev->websockify_values;
    }
    if (conf->upstream.buffer_size == 0){
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
            // hack for empty reply tcp connection
                    wlcf->websockify_values->elts) == NULL)
        {
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
    ctx->encode_send_buf = ngx_create_temp_buf(r->pool, 2 * u->conf->buffer_size); 
    ctx->decode_send_buf = ngx_create_temp_buf(r->pool, 2 * u->conf->buffer_size); 
    //ctx->chunk_size = wlcf->chunk_size;

    ctx->ws_key.len  = 0;
    ctx->ws_key.data = NULL;
    ctx->header_processed = 0;

    ctx->buf_cleanup_ev.log     = r->connection->log;
    ctx->buf_cleanup_ev.data    = ctx;
    ctx->buf_cleanup_ev.handler = ngx_http_websockify_buf_cleanup;

    if (!ctx->encode_send_buf || !ctx->decode_send_buf){
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
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;
    //ngx_uint_t                   rc;
    ngx_http_websockify_ctx_t   *ctx;
    ngx_sha1_t                   sha1;


    part = &r->headers_in.headers.part;
    h = part->elts;

    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    if ( ctx == NULL ) {
        return NGX_ERROR;
    }

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (ngx_strncasecmp(h[i].key.data, (u_char *) "Sec-WebSocket-Key", h[i].key.len) == 0){
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "websockify : found SEC_WEBSOCKET_KEY : %s", h[i].value.data);

            if ( ctx ){
                
                ngx_str_t src;
                src.data = ngx_palloc(r->pool, 20 * sizeof(u_char));
                src.len = 20;

                if (src.data == NULL){
                    return NGX_ERROR;
                }

                ngx_sha1_init(&sha1);
                ngx_sha1_update(&sha1, h[i].value.data, h[i].value.len);
                ngx_sha1_update(&sha1, HYBI_GUID, 36);
                ngx_sha1_final(src.data, &sha1);

                ctx->ws_key.len = HYBI10_ACCEPTHDRLEN; //MAX ACCEPT
                ctx->ws_key.data = ngx_palloc(r->pool, HYBI10_ACCEPTHDRLEN);

                if ( ctx->ws_key.data == NULL){
                    return NGX_ERROR;
                }

                ngx_encode_base64(&ctx->ws_key, &src);

                // this sucks
                r->upstream->request_sent = 1;

                break;
            }

        }
    }

    return NGX_OK;
}

static ssize_t 
ngx_http_websockify_empty_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    return 1;
}

static ngx_int_t
ngx_http_websockify_reinit_request(ngx_http_request_t *r)
{
    ngx_http_upstream_t         *u;
    ngx_http_websockify_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    if (ctx->header_processed ){
        return NGX_OK;
    }

    u = r->upstream;

    // hack for empty reply tcp connection
    original_ngx_upstream_recv = u->peer.connection->recv;
    u->peer.connection->recv = ngx_http_websockify_empty_recv;

    u->read_event_handler(r, r->upstream);

    return NGX_OK;
}

static ngx_int_t
ngx_http_websockify_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t         *u;
    ngx_table_elt_t             *h;
    ngx_http_websockify_ctx_t   *ctx;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "websockify : ngx_http_websockify_process_header");

    ctx = ngx_http_get_module_ctx(r, ngx_http_websockify_module);

    if ( ctx == NULL ) {
        return NGX_ERROR;
    }

    ctx->header_processed = 1;

    u = r->upstream;
    u->peer.connection->recv = original_ngx_upstream_recv;
    u->buffer.last = u->buffer.start;

    if ( ctx->ws_key.len > 0 ) {

        u->headers_in.status_n = NGX_HTTP_SWITCHING_PROTOCOLS;
        ngx_str_set(&u->headers_in.status_line, "101 Switching Protocols");
        u->headers_in.content_length_n = -1;

        h = ngx_list_push(&r->headers_out.headers);
        h->hash = 1;
        ngx_str_set(&h->key, "Sec-WebSocket-Accept");
        h->value = ctx->ws_key;

        h = ngx_list_push(&r->headers_out.headers);
        h->hash = 1;
        ngx_str_set(&h->key, "Upgrade");
        ngx_str_set(&h->value, "websocket");

        h = ngx_list_push(&r->headers_out.headers);
        h->hash = 1;
        ngx_str_set(&h->key, "Sec-WebSocket-Protocol");
        //ngx_str_set(&h->value, "base64");
        ngx_str_set(&h->value, "binary");


        u->state->status = u->headers_in.status_n;
        u->upgrade = 1;

        if ( r->connection->send != ngx_http_websockify_send_with_encode ){
            original_ngx_send_with_encode = r->connection->send;
            r->connection->send = ngx_http_websockify_send_with_encode;
        }

        if ( r->upstream->peer.connection->send != ngx_http_websockify_send_with_decode ){
            original_ngx_send_with_decode = r->upstream->peer.connection->send;
            r->upstream->peer.connection->send = ngx_http_websockify_send_with_decode;
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
    if (wlcf->upstream.upstream == NULL){
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
