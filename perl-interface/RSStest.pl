#!/usr/bin/env perl

use strict;
use warnings;
use File::Basename; 
use Cwd 'abs_path';
use lib dirname(abs_path($0));
use RSScript;
use Data::Dump qw(dump);
use File::Slurp;

my $out;
open ($out, '>', "/tmp/outttt");
my $rq = read_file $ARGV[0];
print { $out } $rq;

my @fakeARGV = ("/tmp/request.txt", "/tmp/response.txt", "/tmp/info.txt");

my $web = RSScript->new(@ARGV);
print { $out } $web->get_ip;

print { $out } dump($web->get_request());
$web->dump_nonheader;

if(!$web->is_authed) {
	print "not authed!";
	$web->set_authed;
}
$web->contenttype("text/html");
$web->responsetype(200);
my $cookie = {name => "foo" , value => "bar", "Max-Age" => 600, "HttpOnly" => undef};
$web->set_cookie($cookie);
my $cookie2 = {name => "bar" , value => "baz lalala?;", "Max-Age" => 600, "HttpOnly" => undef};
$web->set_cookie($cookie2);
my @response = qw (a b);
#$web->respond("a\nb\n");
$web->respond(@response);
$web->submit;
$rq = read_file $ARGV[1];
print { $out } $rq;
close $out;
