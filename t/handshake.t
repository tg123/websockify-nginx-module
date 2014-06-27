use lib 'lib';
use Test::Nginx::Socket;

plan tests => 5 * blocks();

run_tests();

__DATA__

=== TEST 1: websocket handshake
--- config
    location /websockify {
    	websockify_pass 0:5901;
    }
--- tcp_listen: 5901
--- tcp_reply: RFB
--- raw_request eval
["GET /websockify_pass HTTP/1.1\r
Host: localhost\r
Origin:http://0\r
Sec-WebSocket-Key:n2wfgJF+qto2ahU4+aoNkQ==\r
Sec-WebSocket-Protocol:base64\r
Sec-WebSocket-Version:13\r
Upgrade:websocket/",
"data ask for tcp reply\r
Content-Length:1\r\n\r\n0"]
--- error_code: 101
--- response_headers
Connection:upgrade
Sec-WebSocket-Accept:avyE+tn9ibLdRUFx8CXeJlSusVA=
Sec-WebSocket-Protocol:base64
Upgrade:websocket
