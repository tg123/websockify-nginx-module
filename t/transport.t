use IO::Socket::INET;
use IO::Select;
use Protocol::WebSocket::Client;
use Test::Nginx::Socket;
#use Test::More;
use Scope::OnExit;

my $XTcpServerPid;

sub kill_tcp_server() {
    if (defined $XTcpServerPid) {
        Test::Nginx::Util::kill_process($XTcpServerPid, 1);
        undef $XTcpServerPid;
    }
}

# tcp_listen only respones once, make one myself. echo server only
# x_tcp_listen {{{
add_block_preprocessor(sub {
    my $block = shift;

    $block->set_value("request", "GET /");

    if (defined $block->x_tcp_listen) {
        kill_tcp_server();

        my $pid = fork();

        if (!defined $pid) {
            bail_out($block->name . " fork() failed: $!");

        } elsif ($pid == 0) {

            my $server = IO::Socket::INET->new (
                Proto     => 'tcp',
                LocalHost => '127.0.0.1',
                LocalPort => $block->x_tcp_listen,
                Listen    => 5,
                Reuse     => 1,
            ) or bail_out("cannot create listen to " . $block->x_tcp_listen);

            #$server->autoflush(1);

            while (1) {
                my $client = $server->accept();

                while(1) {
                    my $buf;
                    $client->recv($buf, 4096);
                    last if not $client->send($buf);
                    sleep 1;
                }
            }

        } else {
            # main
            $XTcpServerPid = $pid;
        }
    }

    return $block;
});
# }}}

add_response_body_check(sub {
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;

    on_scope_exit { kill_tcp_server(); };

    return unless defined $block->websockify_url;

    my $url = $block->websockify_url;

    my $socket = IO::Socket::INET->new (
        PeerHost => '127.0.0.1',
        PeerPort => $ENV{TEST_NGINX_SERVER_PORT},
        Proto => 'tcp',
    ) or bail_out ("cannont connect to server");

    my $client = Protocol::WebSocket::Client->new(url => 'ws://127.0.0.1:' . $ENV{TEST_NGINX_SERVER_PORT} . $url);

    my $protocol = "binary";
    $protocol = $block->websockify_protocol if defined $block->websockify_protocol;

    my @expect_resp = @{ $block->websockify_frame_response };

    $client->on(
        read => sub {
            my $client = shift;
            my ($resp) = @_;

            my $expect = shift @expect_resp;

            is_str($resp, $expect);
        }
    );

    $client->on(
        error => sub {
            my $client = shift;
            my ($error) = @_;

            bail_out($error);
        }
    );

    $client->on(
        write => sub {
            my $client = shift;
            my ($buf) = @_;

            if (!$client->{hs}->is_done) {
                $buf =~ s/(Sec-WebSocket-Version.*)\r/$1\r\nSec-WebSocket-Protocol: $protocol/;
            }

            $socket->send($buf);
        }
    );

    $client->connect();

    my $buf;

    foreach (@{ $block->websockify_frame_request}) {
        # send
        $client->write($_);

        # recv
        $socket->recv($buf, 65535 + 4 + 4); # max frame size
        $client->read($buf);
    }

    while ( @expect_resp ) {
        $socket->recv($buf, 65535 + 4 + 4); # max frame size
        $client->read($buf);
        
    }
});

# a bit stupid 
plan tests => 23;

run_tests();

__DATA__
=== TEST 1: send and recv binary data
--- config
location /websockify {
    websockify_pass 127.0.0.1:5901;
}
--- websockify_url: /websockify
--- x_tcp_listen: 5901
--- websockify_frame_request eval
["hello", "world"]
--- websockify_frame_response eval
["hello", "world"]


=== TEST 2: send and recv base64 data
--- config
location /websockify {
    websockify_pass 127.0.0.1:5901;
}
--- websockify_url: /websockify
--- x_tcp_listen: 5901
--- websockify_protocol: base64
--- websockify_frame_request eval
["aGVsbG8=", "d29ybGQ="]
--- websockify_frame_response eval
["aGVsbG8=", "d29ybGQ="]


=== TEST 3: big packet
--- config
location /websockify {
    websockify_pass 127.0.0.1:5901;
}
--- websockify_url: /websockify
--- x_tcp_listen: 5901
--- websockify_frame_request eval
["0" x 65535, "0"]
--- websockify_frame_response eval
[ ("0" x 4096) x 16 ]
