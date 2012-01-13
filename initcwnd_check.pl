#!/usr/bin/env perl

use warnings;
use strict;
use Net::RawIP;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Socket qw(inet_ntoa);
use POSIX qw(ceil);

$SIG{INT} = \&finish;

# args
my $dev    = $ARGV[0] or &usage();
my $uri    = $ARGV[1] or &usage();
my $dst_ip = $ARGV[2] or undef;
my $src_ip = undef;

# find local ip
foreach my $ip (`/sbin/ip addr show dev $dev`) {
	if($ip =~ m/inet ([0-9\.]+)\/.+$dev$/) {
		$src_ip = $1;
	}
}
if(!defined $src_ip) {
	die "! can't find local ip\n";
}

# default values
my $now       = time;
my $src_port  = 1024 + int(rand(6000));
my $dst_port  = 80;

my $src_seq   = int(rand(2**32) + 1);
my $dst_seq   = undef ;
my $dst_seq_last  = undef;
my $mss       = 1460;
my $pack_mss  = pack('n', $mss);

my $rwnd_size = 0;
my $cwnd_size = 0;

my $uri_host = undef;
my $uri_path = "/";

# url parsing
if($uri =~ /^http:\/\/([a-z0-9\.]+)(:([0-9]+)|)(\/.*|)$/i) {
	$uri_host = $1;
	if($3) { $dst_port = $3; }
	if($4) { $uri_path = $4; }
} else {
	print STDERR "! invalid uri: $uri\n";
	&usage();
}

if($uri_host && !defined $dst_ip) {
	my $pack_ip = gethostbyname($uri_host);
	if(defined $pack_ip) {
		$dst_ip = inet_ntoa($pack_ip);
	} else {
		print STDERR "! can't find domain: $uri_host\n";
		&usage();
	}
}

my $http_req = "GET $uri_path HTTP/1.1
Host: $uri_host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/534.52.7 (KHTML, like Gecko) Version/5.1.2 Safari/534.52.7
Accept-Encoding: compress, gzip
Accept: */*\n\n";
my $http_req_len = length($http_req);

# pcap
my $pcap        = '';
my $err         = '';
my $filter_str  = "ip and tcp";
my $filter      = '';
my $snaplen     = 1500 ;
my $timeout     = 0;
my ($net,$mask) = 0;

# RST packet drop for raw socket
my $iptables = "OUTPUT -p tcp --tcp-flags RST RST -s $src_ip --sport $src_port -d $dst_ip --dport $dst_port -j DROP";
system("/sbin/iptables -A $iptables");

# init pcap
Net::Pcap::pcap_lookupnet($dev, \$net, \$mask, \$err);
$pcap = &Net::Pcap::pcap_open_live($dev, $snaplen, 1, $timeout, \$err);
if (Net::Pcap::compile($pcap, \$filter, $filter_str, 0, $mask)) {
	print STDERR "! error compiling capture filter!\n";
	exit 1;
}
Net::Pcap::pcap_setnonblock($pcap, 1, \$err);

my $syn_pkt = make_packet($src_ip, $src_port, $dst_ip, $dst_port, $src_seq, undef, 1, 0, 0, 0, 65535, undef);

$syn_pkt->send();
$src_seq++;

$now = time;
while (!defined $dst_seq) {
	Net::Pcap::pcap_dispatch($pcap, 1, \&receive_synack, '');
	if($now <= time-3) {
		print STDERR "! connection timeout\n";
		finish();
	}
}
print STDERR "+ connected from $src_ip:$src_port to $dst_ip:$dst_port\n";

my $ack_pkt = make_packet($src_ip, $src_port, $dst_ip, $dst_port, $src_seq, $dst_seq, 0, 1, 0, 0, 65535, undef);
$ack_pkt->send();

my $data_pkt = make_packet($src_ip, $src_port, $dst_ip, $dst_port, $src_seq, $dst_seq, 0, 1, 1, 0, 65535, $http_req);
$data_pkt->send();

$now = time;
Net::Pcap::pcap_loop($pcap, -1, \&check_cwnd, '');

finish();

sub usage( ) {
	die "usage: $0 <dev> <uri> (<dst_ip>)\n";
}

sub finish {
	system("/sbin/iptables -D $iptables");
	my $rst_pkt = make_packet($src_ip, $src_port, $dst_ip, $dst_port, $src_seq + $http_req_len, undef, 0, 0, 0, 1, 65535, undef);
	$rst_pkt->send();
	if($pcap) {
		Net::Pcap::close ($pcap);
	}
	if($cwnd_size > 0 && $rwnd_size > 0) {
		print "* $uri_host ($dst_ip) - init_cwnd: ".ceil($cwnd_size/$mss)." (".$cwnd_size." byte), init_rwnd: ".ceil($rwnd_size/$mss)." (".$rwnd_size." byte)\n";
	}
	exit 0;
}

sub make_packet {
	my ($src_ip, $src_port, $dst_ip, $dst_port, $src_seq, $dst_seq, $syn, $ack, $psh, $rst, $window_size, $data) = @_;
	my $pkt = Net::RawIP->new({
		ip => {
			saddr => $src_ip,
			daddr => $dst_ip
		},
		tcp => {
			source => $src_port,
			dest => $dst_port,
			seq => $src_seq,
			ack_seq => $dst_seq,
			syn => $syn,
			ack => $ack,
			psh => $psh,
			rst => $rst,
			window => $window_size,
			data => $data
		}
	});
	$pkt->optset(tcp => {type => [2], data => [$pack_mss]});

	return $pkt;
}

# receive packet parser
sub receive_packet {
	my ($data, $hdr, $pkt) = @_ ;

	if (!$pkt || !defined($hdr) || !defined($pkt)) {
		print STDERR "! invalid packet!\n";
		return undef;
	}

	my $eth = NetPacket::Ethernet->decode($pkt);
	my $ip  = NetPacket::IP->decode($eth->{data});
	my $tcp = NetPacket::TCP->decode($ip->{data});
	if ($ip->{proto} != NetPacket::IP::IP_PROTO_TCP) {
		return undef;
	}

	my $seq = $tcp->{seqnum};
	my $ack = $tcp->{acknum};
	my $win = $tcp->{winsize};
	my $len = length($tcp->{data});

	my @return = ($seq, $ack, $len, $win);
	return @return;
}

sub check_cwnd {
	my ($seq, $ack, $len, $win) = receive_packet(@_);

	if ((defined $seq && $seq) && ($ack == ($src_seq + $http_req_len))) {
		if(!defined $dst_seq_last || $dst_seq_last <= $seq) {
			$cwnd_size += $len;
			$dst_seq_last = $seq;
		} else {
			finish();
		}
	}
	if($now <= time-3) {
		finish();
	}
}

# get ack no of synack packet
sub receive_synack {
	my ($seq, $ack, $len, $win) = receive_packet(@_);
	$rwnd_size = $win;

	if ((defined $seq && $seq) && ($ack == $src_seq)) {
		$dst_seq = $seq + 1;
	}   
}

