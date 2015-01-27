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

#ifndef _WEBSOCKET_H_INCLUDED_
#define _WEBSOCKET_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


#define HYBI_GUID                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define HYBI10_ACCEPTHDRLEN      29

#define MAX_WEBSOCKET_FRAME_SIZE 65535


//    https://tools.ietf.org/html/rfc6455#section-5.1
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-------+-+-------------+-------------------------------+
//    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//    | |1|2|3|       |K|             |                               |
//    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//    |     Extended payload length continued, if payload len == 127  |
//    + - - - - - - - - - - - - - - - +-------------------------------+
//    |                               |Masking-key, if MASK set to 1  |
//    +-------------------------------+-------------------------------+
//    | Masking-key (continued)       |          Payload Data         |
//    +-------------------------------- - - - - - - - - - - - - - - - +
//    :                     Payload Data continued ...                :
//    + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//    |                     Payload Data continued ...                |
//    +---------------------------------------------------------------+


#define WEBSOCKET_OPCODE_CONTINUATION  0x0
#define WEBSOCKET_OPCODE_TEXT          0x1
#define WEBSOCKET_OPCODE_BINARY        0x2

#define WEBSOCKET_OPCODE_CLOSE         0x8
#define WEBSOCKET_OPCODE_PING          0x9
#define WEBSOCKET_OPCODE_PONG          0xA


typedef struct websocket_frame_s {
    u_char     opcode;
    size_t     payload_length;

    u_char    *mask;
    u_char    *payload;
} websocket_frame_t;

#define MIN_WEBSOCKET_FRAME_HEADER_SIZE 2
#define MAX_WEBSOCKET_FRAME_HEADER_SIZE 4
#define WEBSOCKET_FRAME_MASK_SIZE       4


// for server encode only
#define websocket_server_encoded_header_length(size)  (((size) <= 125) ? (MIN_WEBSOCKET_FRAME_HEADER_SIZE) : (MAX_WEBSOCKET_FRAME_HEADER_SIZE))
#define websocket_server_encoded_length(size)         (websocket_server_encoded_header_length(size) + size)

#define websocket_server_decoded_header_length(size)  (websocket_server_encoded_header_length(size) + WEBSOCKET_FRAME_MASK_SIZE)

// 1 char frame
#define MIN_SERVER_FRAME_BASE64_SIZE (websocket_server_encoded_header_length(1) + ngx_base64_encoded_length(1))
#define MIN_SERVER_FRAME_BINARY_SIZE (websocket_server_encoded_header_length(1) + 1)
#define MIN_SERVER_FRAME_SIZE        (ngx_max(MIN_SERVER_FRAME_BASE64_SIZE, MIN_SERVER_FRAME_BINARY_SIZE))

#define websocket_payload_consume_size(size)  ( (size) <= ( websocket_server_encoded_header_length(125) + 125 ) ? ( size - MIN_WEBSOCKET_FRAME_HEADER_SIZE ) : ( size - MAX_WEBSOCKET_FRAME_HEADER_SIZE) )

static ngx_inline void
websocket_server_write_frame_header(u_char *dst, u_char opcode,
                                    size_t payload_length)
{
    dst[0] = (u_char)((opcode & 0x0F) | 0x80);
    if ( payload_length <= 125 ) {
        dst[1] = (u_char)(payload_length);
    } else {
        dst[1] = (u_char) 126;
        *(u_short *)&(dst[2]) = htons((u_short)(payload_length));
    }
}

static ngx_inline ssize_t
websocket_server_decode_next_frame(websocket_frame_t *frame, u_char *src,
                                   size_t size)
{
    size_t     header_length;
    size_t     payload_length;

    if (size < MIN_WEBSOCKET_FRAME_HEADER_SIZE) {
        return NGX_AGAIN;
    }

    frame->opcode = src[0] & 0x0F;

    payload_length = src[1] & 0x7F;

    if (payload_length == 126) {
        payload_length = (src[2] << 8) + src[3];
    } else if (payload_length == 127) {
        // only max frame payload 65535 support at this time
        return NGX_ERROR;
    }

    frame->payload_length = payload_length;

    header_length = websocket_server_decoded_header_length(payload_length);

    // no enough body
    if (header_length + payload_length > size) {
        return NGX_AGAIN;
    }

    frame->mask    = src + header_length - WEBSOCKET_FRAME_MASK_SIZE;
    frame->payload = src + header_length;

    return header_length;
}

static ngx_inline void
websocket_server_decode_unmask_payload(websocket_frame_t *frame)
{
    size_t     i;
    for (i = 0; i < frame->payload_length; i++) {
        frame->payload[i] ^= frame->mask[i % 4];
    }
}

#endif /* _WEBSOCKET_H_INCLUDED_ */
