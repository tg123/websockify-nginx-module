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

    u_char    *payload;
} websocket_frame_t;

#define MIN_WEBSOCKET_FRAME_HEADER_SIZE 2
#define MAX_WEBSOCKET_FRAME_HEADER_SIZE 4
#define WEBSOCKET_FRAME_MASK_SIZE       4


// for server encode only
#define websocket_server_encoded_header_length(size)  (((size) <= 125) ? (MIN_WEBSOCKET_FRAME_HEADER_SIZE) : (MAX_WEBSOCKET_FRAME_HEADER_SIZE))
#define websocket_server_encoded_length(size)         (websocket_server_encoded_header_length(size) + size)

// 1 char frame
#define MIN_SERVER_FRAME_BASE64_SIZE (websocket_server_encoded_header_length(1) + ngx_base64_encoded_length(1))
#define MIN_SERVER_FRAME_BINARY_SIZE (websocket_server_encoded_header_length(1) + 1)
#define MIN_SERVER_FRAME_SIZE        (ngx_max(MIN_SERVER_FRAME_BASE64_SIZE, MIN_SERVER_FRAME_BINARY_SIZE))

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

#endif /* _WEBSOCKET_H_INCLUDED_ */
