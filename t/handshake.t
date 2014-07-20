use lib 'lib';
use Test::Nginx::Socket;

plan tests => 13;

log_level('debug');

run_tests();

__DATA__

=== TEST 1: websocket handshake
--- config
    location /websockify {
    	websockify_pass 0:5901;
    }
--- tcp_listen: 5901
--- tcp_reply: RFB
--- request
    GET /websockify
--- more_headers
Origin:http://0
Sec-WebSocket-Key:n2wfgJF+qto2ahU4+aoNkQ==
Sec-WebSocket-Protocol:base64
Sec-WebSocket-Version:13
Upgrade:websocket
--- error_code: 101
--- response_headers
Connection:upgrade
Sec-WebSocket-Accept:avyE+tn9ibLdRUFx8CXeJlSusVA=
Sec-WebSocket-Protocol:base64
Upgrade:websocket
--- abort



=== TEST 2: bad upstream
--- config
    location /websockify {
    	websockify_pass 0:5901;
    }
--- request
    GET /websockify
--- more_headers
Origin:http://0
Sec-WebSocket-Key:n2wfgJF+qto2ahU4+aoNkQ==
Sec-WebSocket-Protocol:base64
Sec-WebSocket-Version:13
Upgrade:websocket
--- error_code: 502



=== TEST 3: bad handshake header
--- config
    location /websockify {
    	websockify_pass 0:5901;
    }
--- tcp_listen: 5901
--- tcp_reply: RFB
--- request
GET /websockify
--- error_code: 400
--- abort


=== TEST 4: select protocol
--- config
    location /websockify {
    	websockify_pass 0:5901;
    }
--- tcp_listen: 5901
--- tcp_reply: RFB
--- request
    GET /websockify
--- more_headers
Origin:http://0
Sec-WebSocket-Key:n2wfgJF+qto2ahU4+aoNkQ==
Sec-WebSocket-Protocol:base64, binary
Sec-WebSocket-Version:13
Upgrade:websocket
--- error_code: 101
--- response_headers
Connection:upgrade
Sec-WebSocket-Accept:avyE+tn9ibLdRUFx8CXeJlSusVA=
Sec-WebSocket-Protocol:binary
Upgrade:websocket
--- abort



=== TEST 5: unsupported protocol 
--- config
    location /websockify {
    	websockify_pass 0:5901;
    }
--- tcp_listen: 5901
--- tcp_reply: RFB
--- request
    GET /websockify
--- more_headers
Origin:http://0
Sec-WebSocket-Key:n2wfgJF+qto2ahU4+aoNkQ==
Sec-WebSocket-Protocol: unsupported
Sec-WebSocket-Version:13
Upgrade:websocket
--- error_code: 400
--- abort
