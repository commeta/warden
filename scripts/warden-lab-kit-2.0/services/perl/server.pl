#!/usr/bin/perl
# Warden Lab microservice — Perl (core IO::Socket::INET, prefork).
# No CPAN modules beyond core. Models a prefork worker pool.
use strict; use warnings;
use IO::Socket::INET;
use POSIX ':sys_wait_h';

my $ROOT = $ENV{LAB_ROOT} || '/tmp';
my $PORT = $ENV{PORT} || 3107;

sub urldecode { my $s = shift; $s =~ s/\+/ /g; $s =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge; return $s; }
sub qparse { my %q; for (split /&/, shift // '') { my ($k,$v)=split/=/,$_,2; $q{urldecode($k)}=urldecode($v//'') if defined $k; } return %q; }
sub item { my $id = shift; my $o = `/usr/bin/sqlite3 -readonly $ROOT/data/items.sqlite "SELECT id||'|'||name||'|'||note FROM items WHERE id = $id" 2>/dev/null`; return $o eq '' ? 'no result' : $o; }

sub handle {
    my $c = shift;
    my $line = <$c>; return unless $line;
    my ($method,$target) = split /\s+/, $line;
    my $clen = 0;
    while (my $h = <$c>) { last if $h =~ /^\r?$/; $clen = $1 if $h =~ /^Content-Length:\s*(\d+)/i; }
    my $body=''; if ($clen) { read($c,$body,$clen>262144?262144:$clen); }
    my $uri = $target; $uri =~ s{^/svc/[^/]+}{}; $uri='/' if $uri eq '';
    my ($path,$qs) = split /\?/, $uri, 2;
    my %q = qparse($qs);
    my ($code,$text) = (200,'not found');
    if ($path eq '/health') { $text='ok'; }
    elsif ($path eq '/echo') { $text='echo: '.($q{q}//''); }
    elsif ($path eq '/item') { $text=item($q{id}//'1'); }
    elsif ($path eq '/spawn') { $text=`/usr/bin/id`.'spawned'; }
    elsif ($path eq '/sleep') { my $ms=($q{ms}//0); $ms=10000 if $ms>10000; select(undef,undef,undef,$ms/1000); $text='slept'; }
    elsif ($path eq '/alloc') { my $mb=($q{mb}//1); $mb=1 if $mb<1; $mb=256 if $mb>256; my $buf="\x01" x ($mb*1024*1024); $text="alloc $mb (".length($buf).")"; }
    elsif ($path eq '/upload') {
        if ($method eq 'POST') { mkdir "$ROOT/uploads"; my $name=($q{name}//'upload.bin'); $name=~s/[^A-Za-z0-9._-]/_/g;
            open(my $f,'>',"$ROOT/uploads/$name"); binmode $f; print $f $body; close $f; $text="stored uploads/$name"; }
        else { $code=405; $text='POST'; }
    } else { $code=404; }
    my $len = length($text);
    print $c "HTTP/1.1 $code X\r\nContent-Type: text/plain; charset=utf-8\r\nX-Lab-Service: perl\r\nContent-Length: $len\r\nConnection: close\r\n\r\n$text";
    close $c;
}

$SIG{CHLD}='IGNORE';
my $srv = IO::Socket::INET->new(LocalHost=>'127.0.0.1',LocalPort=>$PORT,Listen=>128,ReuseAddr=>1,Proto=>'tcp') or die "listen: $!";
for (1..3) {
    my $pid = fork; if (!$pid) { while (my $c = $srv->accept) { handle($c); } exit; }
}
1 while wait() != -1;
