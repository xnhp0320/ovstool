#!/usr/bin/perl

use warnings;
use strict;
use v5.24;

use Getopt::Std;
use Data::Dumper;

our ($opt_f);
getopt('f:');

my $IPFMT = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';
my $HEXFMT = '0x[a-f0-9]+|0';
my $MACFMT = '(?:[\da-f]{2}:){5}[\da-f]{2}';
my $IPMASK_FMT = "$IPFMT(/$IPFMT)?";
my $PORTFMT = '[0-9]+(/0x[a-f0-9]+)?';
my $VALUEFMT = $PORTFMT;

my $IPV6_SEG = '[a-f0-9]{1,4}';

sub parse_ipv4 {
    my ($line, $f) = (\$_[0], $_[1]);
    $$line =~ /\G\(/g;

    while ($$line !~ /\G\)/gc) {
        if ($$line =~ /\Gdst=($IPMASK_FMT),?/gc) {
            $f->{dst} = $1;
            next;
        }

        if ($$line =~ /\Gsrc=($IPMASK_FMT),?/gc) {
            $f->{src} = $1;
            next;
        }

        if ($$line =~ /\Gproto=(\d+),?/gc) {
            $f->{proto} = $1;
            next;
        }

        if ($$line =~ /\Gfrag=(no|first|later),?/gc) {
            $f->{frag} = $1;
            next;
        }

        say "unknown field at " . pos($$line) . ":";
        say substr($$line, pos($$line), length($$line) - pos($$line));
        die;
    }

    $$line =~ /,\s*/gc;
}

sub parse_eth {
    my ($line, $f) = (\$_[0], $_[1]);
    $$line =~ /\G\(/g;

    while ($$line !~ /\G\)/gc) {
        if ($$line =~ /\Gdst=($MACFMT),?/gc) {
            $f->{dst} = $1;
            next;
        }

        if ($$line =~ /\Gsrc=($MACFMT),?/gc) {
            $f->{src} = $1;
            next;
        }

        say "unknown field at " . pos($$line) . ":";
        say substr($$line, pos($$line), length($$line) - pos($$line));
        die;
    }

    $$line =~ /,\s*/gc;
}

sub parse_actions {
    my ($line, $f) = (\$_[0], $_[1]);
    $$line =~ /\G:/g;
    $f->{actions} = substr($$line, pos($$line), length($$line) - pos($$line));
    $$line =~ /\G.*$/g;
}

sub eat_bracket_content {
    my $line = shift;
    my $bracket = 1;
    while ($bracket) {
        #say substr($$line, pos($$line), 1);
        if ($$line =~ /\G\(/gc) {
            $bracket ++;
        }
        $$line =~ /\G[^\)]*/g;
        if ($$line =~ /\G\)/gc) {
            $bracket --;
        }
    }
}

sub parse_tunnel {
    my ($line, $f) = (\$_[0], $_[1]);
    $$line =~ /\G\(/g;
    while(not ($$line =~ /\G\)/gc)) {
        if ($$line =~ /\Gtun_id=($HEXFMT),?/gc) {
            $f->{tun_id} = $1;
            next;
        }

        if ($$line =~ /\Gsrc=($IPFMT),?/gc) {
            $f->{src} = $1;
            next;
        }

        if ($$line =~ /\Gdst=($IPFMT),?/gc) {
            $f->{dst} = $1;
            next;
        }

        if ($$line =~ /\Gtp_dst=(\d+),?/gc) {
            $f->{tp_dst} = $1;
            next;
        }

        if ($$line =~ /\Gflags\(/gc) {
            eat_bracket_content($line); 
            next;
        }

        if ($$line =~ /\Gtos=($HEXFMT),?/gc) {
            $f->{tun_tos} = $1;
            next;
        }

        say "unknown field at " . pos($$line) . ":";
        say substr($$line, pos($$line), length($$line) - pos($$line));
        die;
    }
    $$line=~ /\G,\s*/g;
}

sub parse_udp {
    my ($line, $f) = (\$_[0], $_[1]);
    $$line =~ /\G\(/g;
    while(not ($$line =~ /\G\)/gc)) {

        if ($$line =~ /\Gsrc=($PORTFMT),?/gc) {
            $f->{sport} = $1;
            next;
        }

        if ($$line =~ /\Gdst=($PORTFMT),?/gc) {
            $f->{dport} = $1;
            next;
        }

        say "unknown field at " . pos($$line) . ":";
        say substr($$line, pos($$line), length($$line) - pos($$line));
        die;
    }

    $$line=~ /\G,\s*/g;
}

sub parse_ipv6_addr {
    my $line = \$_[0];
    my $addr = "";

OUTSIDE:
    while (1) {
        while ($$line =~ /\G(${IPV6_SEG}:)/gc) {
            $addr .= $1;
        }
        if ($$line =~ /\G:/gc) {
            $addr .= ":";
        } elsif ($$line =~ /\G($IPV6_SEG)/gc) {
            $addr .= $1;
            last OUTSIDE;
        } else {
            last OUTSIDE;
        }
    }
    $$line =~ /\G,?/gc;
    return $addr;
}

sub parse_ipv6 {
    my ($line, $f) = (\$_[0], $_[1]);
    $$line =~ /\G\(/g;

    while(not ($$line =~ /\G\)/gc)) {
        if ($$line =~ /\Gsrc=/gc) {
            $f->{src} = parse_ipv6_addr($$line);
            next;
        }

        if ($$line =~ /\Gdst=/gc) {
            $f->{dst} = parse_ipv6_addr($$line);
            next;
        }

        if ($$line =~ /\Gproto=(\d+),?/gc) {
            $f->{proto} = $1;
            next;
        }

        if ($$line =~ /\Gfrag=(no|first|later),?/gc) {
            $f->{frag} = $1;
            next;
        }

        say "unknown field at " . pos($$line) . ":";
        say substr($$line, pos($$line), length($$line) - pos($$line));
        die;
    }

    $$line=~ /\G,\s*/g;
}

sub parse_icmpv6 {
    my ($line, $f) = (\$_[0], $_[1]);
    $$line =~ /\G\(/g;

    while ($$line !~ /\G\)/gc) {
        if ($$line =~ /type=($VALUEFMT),?/gc) {
            $f->{icmp_type} = $1;
            next;
        }

        say "unknown field at " . pos($$line) . ":";
        say substr($$line, pos($$line), length($$line) - pos($$line));
        die;
    }

    $$line=~ /\G,\s*/g;
}

sub parse {
    my $line = shift;
    my $f = {};

    my %parse_func = (
        recirc_id => sub { 
            die if $line !~ /\G\(($HEXFMT)\)/g;
            $f->{recirc_id} = $1; 
            $line =~ /\G,\s*/g;
        },

        tunnel => \&parse_tunnel,

        in_port => sub {
            die if $line !~ /\G\(([\w-]+)\)/g;
            $f->{in_port} = $1;
            $line =~ /\G,\s*/g;
        },

        eth => \&parse_eth,

        eth_type => sub {
            die if $line !~ /\G\(($HEXFMT)\)/g;
            $f->{eth_type} = $1;
            $line =~ /\G,\s*/g;
        },

        ipv4 => \&parse_ipv4,

        packets => sub {
            die if $line !~ /\G:(\d+)/g;
            $f->{packets} = $1;
            $line =~ /\G,\s*/g;
        },

        bytes => sub {
            die if $line !~ /\G:(\d+)/g;
            $f->{bytes} = $1;
            $line =~ /\G,\s*/g;
        },

        used => sub {
            die if $line !~ /\G:([\d\.]+)s|never/g;
            $f->{used} = $1 // "never";
            $line =~ /\G,\s*/g;
        },

        udp => \&parse_udp,
        ipv6 => \&parse_ipv6,
        icmpv6 => \&parse_icmpv6,

        actions => \&parse_actions
        
    );

    while ($line =~ /([a-z0-9_]+)/g) {
        die "undefine $1 handler" if !defined($parse_func{$1});
        $parse_func{$1}($line, $f);
    }

    return $f;
}

my @flows;

open my $in, "<", $opt_f or die $!;
while (<$in>) {
    chomp;
    my $f = parse($_);
    push @flows, $f;
}
close $in;


print scalar @flows, "\n";
