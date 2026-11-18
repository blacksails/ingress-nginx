#!/usr/bin/perl

# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Regression checks for CVE-2026-123007 and CVE-2026-123633, without an RCE payload.

use warnings;
use strict;

use Socket qw/ SOL_SOCKET SO_RCVBUF /;
use Test::More;

use Test::Nginx;
use Test::Nginx::HTTP2;

my $t = Test::Nginx->new()->has(qw/http http_v2 rewrite debug/)->plan(3)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    http2 on;
    sendfile on;

    server {
        listen       127.0.0.1:8080 sndbuf=4k;
        server_name  localhost;

        location /reuse {
            return 200 "stream ok\n";
        }
    }
}

EOF

$t->write_file('large', 'x' x (2**20));
$t->run();

# A one-byte HEADERS fragment makes an otherwise idle connection reusable.
# Check that stream creation removes it from the reusable queue *before*
# processing its URI, rather than merely checking that the request survives.
my $s = Test::Nginx::HTTP2->new();
my $offset = length($t->read_file('error.log'));
my $sid = $s->new_stream({ path => '/reuse', split => [1] });
my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;
is($frame->{headers}->{':status'}, 200, 'split HEADERS request succeeds');

my $log = substr($t->read_file('error.log'), $offset);
my ($creation) = $log =~ /(http2 HEADERS frame sid:1.*?http uri: "\/reuse")/s;
ok(scalar(($creation || '') =~ /reusable connection: 0/),
	'CVE-2026-123633: active stream is not reusable during URI processing');
undef $s;

# Fill the small TCP buffers so DATA remains queued inside nginx. With the
# connection window initially at its maximum, a 512 KiB increment exceeds
# the window including queued DATA, but not the old, reduced send_window.
$s = Test::Nginx::HTTP2->new();
$s->{socket}->setsockopt(SOL_SOCKET, SO_RCVBUF, 4096) or die $!;
$s->h2_settings(0, 0x4 => 2**20);
$s->h2_window(2**31 - 1 - 65535);
$s->new_stream({ path => '/large' });
select undef, undef, undef, 0.2;
$s->h2_window(2**19);

# Read the error, not the large response: draining it would change the queue.
$log = '';
for (1 .. 100) {
	$log = $t->read_file('error.log');
	last if $log =~ /client violated connection flow control/;
	select undef, undef, undef, 0.02;
}
ok(scalar($log =~ /client violated connection flow control/),
	'CVE-2026-123007: WINDOW_UPDATE accounts for queued DATA');
undef $s;

$t->stop();
