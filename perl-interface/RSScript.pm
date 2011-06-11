#
# author: rofl0r
# 
# License: GPL v3
#


package RSScript;

use strict;
use warnings;
use File::Copy qw(move);

sub url_encode {
	my $str = shift;
	$str =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
	return $str;
}

sub url_decode {
	my $str = shift;
	$str =~ s/%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
	$str =~ s/\+/ /g;
	return $str;
}

sub webchomp {
	my $str = shift;
	$str =~ s/\r?\n$//;
	return $str;
}

sub new {
	my ($pkg, @args) = @_;
	die("need an array with 3 args passed: requeststream-filename, responsestream-filename, infostream-filename.") if(scalar(@args) < 3);
	my $self = {
		failed_handle_msg => "failed to get filehandle",
		request_fn => $args[0],
		response_fn => $args[1],
		info_fn => $args[2],
		info => undef,
		response_err => undef,
		response_arr => [],
		response_len => 0,
		response_contenttype => undef,
		response_cookies => [],
		request => undef,
		authdb => "/tmp/RSSauth-ip.txt",
		authcookiedb => "/tmp/RSSauth-cookie.txt",
		authtimeoutsecs => 30 * 60
	};
	bless $self, $pkg;
}

sub dump_nonheader {
	my $self = shift;
	read_request($self) unless defined($self->{request});
	open my $handle, '<', $self->{request_fn} or die("cannot open info file");
	seek $handle, $self->{request}->{headersize}, 0;
	my $byte;
	while((read $handle, $byte, 1)) {
		print $byte;
	}
	close $handle;
}

sub write_attachment {
	my ($self, $outfilename) = @_;
	read_request($self) unless defined($self->{request});
	open my $handle, '<', $self->{request_fn} or die("cannot open info file");
	open my $outhandle, '>', $outfilename or die("cannot open output file");
	my $fpos = $self->{request}->{headersize} + $self->{request}->{multishitheadersize};
	my $maxpos = $self->{request}->{headersize} + $self->{request}->{"Content-Length"} - (2 + length($self->{request}->{boundary}) + 2 + 2); 
	#it seems we have at the end: \r\nBOUNDARY--\r\n
	seek $handle, $fpos, 0;
	my $byte;
	while((read $handle, $byte, 1) && $fpos < $maxpos) {
		print { $outhandle } $byte;
		$fpos++;
	}
	close $handle;
	close $outhandle;
}

#returns a hash reference, containing the usual stuff such as Content-Type etc, and additionally:
#getparams = parameters passed via url i.e. test.pl?foo=bar&bar=baz
#formdata = data passed via post form
#cookies = hashref of passed cookies
#upload = "filename" if a file is being uploaded via multipart/formdata. only the first attachment can be extracted,
#by using write_attachment.
sub read_request {
	my $self = shift;
	$self->{request} = {};
	$self->{request}->{headersize} = 0;
	$self->{request}->{multishitheadersize} = 0;
	open my $handle, '<', $self->{request_fn} or die("cannot open request file");
	my $i = 0; my $doneheader = 0;
	while(<$handle>) {
		$self->{request}->{headersize} += length($_) unless($doneheader);
		$self->{request}->{multishitheadersize} += length($_) if($doneheader > 0);
		$_ = webchomp($_);
		if ($_ eq "") {
			$doneheader = 1 unless($doneheader);
			next if $doneheader < 4;
			last;
		}
		if(!$i && (/^(GET) ([\/\w\.\?&%=]+) / || /^(POST) ([\/\w\.\?&%=]+) /)) {
			$self->{request}->{method} = $1;
			$self->{request}->{url} = $2;
			my ($uri, $params) = split /\?/, $self->{request}->{url};
			$self->{request}->{uri} = $uri;
			if(defined($params)) {
				my @kvs = split /&/, $params;
				$self->{request}->{getparams} = {};
				for my $kv(@kvs) {
					my ($key, $value) = split /=/, $kv;
					$self->{request}->{getparams}->{url_decode($key)} = defined($value) ? url_decode($value) : undef;
				}
			}
			next;
		}
		if($i && !$doneheader) {
			my ($key, $value) = split /: /, $_;
			if ($key =~ /^Cookie/) {
				$self->{request}->{cookies} = {} unless defined($self->{request}->{cookies});
				my @cookz = split /;/, $value;
				for my $cook(@cookz) {
					$cook =~ s/^ //;
					my ($cookey, $cookval) = split /=/, $cook;
					$self->{request}->{cookies}->{$cookey} = $cookval;
				}
			} else {
				$self->{request}->{$key} = defined($value) ? $value : undef;
			}
		} elsif ($doneheader == 1) {
			if($self->{request}->{method} eq "POST" && 
			defined($self->{request}->{"Content-Type"}) &&
			$self->{request}->{"Content-Type"} =~ /form-urlencoded/) { #Content-Type: application/x-www-form-urlencoded
				my @kvs = split /&/, $_;
				$self->{request}->{formdata} = {};
				for my $kv(@kvs) {
					my ($key, $value) = split /=/, $kv;
					$self->{request}->{formdata}->{url_decode($key)} = defined($value) ? url_decode($value) : undef;
				}
			} elsif ($self->{request}->{method} eq "POST" && 
			defined($self->{request}->{"Content-Type"}) &&
			$self->{request}->{"Content-Type"} =~ /multipart\/form-data; boundary=([-_\w]+)/) {
				$self->{request}->{boundary} = $1; #the actual $_ should contain the boundary
				$doneheader = 2;
			} else {
				#dont read binary stuff that may be in content. we extract that without using ram when needed.
				last;
			}
		} elsif($doneheader == 2) {
			$self->{request}->{upload} = $1, $doneheader = 3 if /filename=\"(.+?)\"/;
		} elsif($doneheader == 3) {
			$doneheader = 4 if /Content-Type/;
		}
		$i++;
	}
	close $handle;
}

sub get_request {
	my $self = shift;
	read_request($self) unless defined($self->{request});
	return $self->{request};
}

sub read_info {
	my $self = shift;
	$self->{info} = {};
	open my $handle, '<', $self->{info_fn} or die("cannot open info file");
	while(<$handle>) {
		$_ = webchomp($_);
		next if $_ eq "";
		my($key, $value) = split /: /, $_;
		$self->{info}->{$key} = $value;
	}
	close $handle;
}

#these two simple auth related subs work only with a persistent connection.
#as soon as the client disconnects/gets disconnected, he's non authed.
#unfortunately most browsers will close conn, so we need an additional way as well...
sub is_authed {
	my $self = shift;
	read_info($self) unless defined($self->{info});
	return defined($self->{info}->{Authorized});
}

sub set_authed {
	my $self = shift;
	read_info($self) unless defined($self->{info});
	$self->{info}->{Authorized} = 1;
	open my $handle, '>', $self->{info_fn} or die("cannot open info file");
	for(keys %{$self->{info}}) {
		next unless(defined($_) || $self->{info}->{$_});
		print { $handle } $_ . ": " . $self->{info}->{$_} . "\n";
	}
	close $handle;
}

#so we use another approach, storing the ip to a textfile.
#this approach doesnt scale well, but is sufficient for a small number of clients

sub is_ip_authed {
	my $self = shift;
	read_info($self) unless defined($self->{info});
	open my $handle, '<', $self->{authdb} or return 0;
	while(<$handle>) {
		chomp;
		my($timeout, $ip) = split /\|/, $_;
		close $handle, return 1 if(($ip eq $self->{info}->{IP}) && ($timeout > time()));
	}
	close $handle;
	return 0;
}

sub set_ip_authed {
	my $self = shift;
	read_info($self) unless defined($self->{info});
	open my $tmp, '>', "/tmp/RSSauth.tmp" or die("cannot open temp file");
	my $handle;
	open $handle, '<', $self->{authdb} or $handle = undef;
	my $done = 0;
	if(defined($handle)) {
		while(<$handle>) {
			chomp;
			my($timeout, $ip) = split /\|/, $_;
			if($ip eq $self->{info}->{IP}) {
				print { $tmp } time() + $self->{authtimeoutsecs} . "|" . $ip . "\n";
				$done = 1;
			} else {
				print { $tmp } $_ . "\n" if $timeout > time();
			}
		}
	}
	print { $tmp } time() + $self->{authtimeoutsecs} . "|" . $self->{info}->{IP} . "\n" unless $done;
	close($tmp);
	close($handle) if (defined($handle));
	unlink $self->{authdb};
	move("/tmp/RSSauth.tmp", $self->{authdb});
}

# third method... use a cookie since tor changes ip addresses frequently,
sub is_cookie_authed {
	my $self = shift;
	read_info($self) unless defined($self->{info});
	my $req = get_request($self);
	return 0 unless defined($req->{cookies}->{auth});
	open my $handle, '<', $self->{authcookiedb} or return 0;
	while(<$handle>) {
		chomp;
		my($timeout, $cookie) = split /\|/, $_;
		close $handle, return 1 if(($cookie eq $req->{cookies}->{auth}) && ($timeout > time()));
	}
	close $handle;
	return 0;
}

sub create_auth_cookie {
	return sprintf("%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X", int(rand(256)), int(rand(256)), int(rand(256)), int(rand(256)),
		int(rand(256)), int(rand(256)), int(rand(256)), int(rand(256)));
}

sub set_cookie_authed {
	my ($self, $cookie) = @_;
	my $authcookie;
	if(!defined($cookie)) {
		my $req = get_request($self);
		die("authcookie not set") unless defined($req->{cookies}->{auth});
		$authcookie = $req->{cookies}->{auth};
	} else {
		$authcookie = $cookie;
	}
	open my $tmp, '>', "/tmp/RSSauth.tmp" or die("cannot open temp file");
	my $handle;
	open $handle, '<', $self->{authcookiedb} or $handle = undef;
	my $done = 0;
	if(defined($handle)) {
		while(<$handle>) {
			chomp;
			my($timeout, $cookie) = split /\|/, $_;
			if($cookie eq $authcookie) {
				print { $tmp } time() + $self->{authtimeoutsecs} . "|" . $cookie . "\n";
				$done = 1;
			} else {
				print { $tmp } $_ . "\n" if $timeout > time();
			}
		}
	}
	print { $tmp } time() + $self->{authtimeoutsecs} . "|" . $authcookie . "\n" unless $done;
	close($tmp);
	close($handle) if (defined($handle));
	unlink $self->{authcookiedb};
	move("/tmp/RSSauth.tmp", $self->{authcookiedb});
}

#shortcut function, use only before you send an actual response, i.e. redirect_soft.
sub make_auth_cookie {
	my($self) = @_;
	my $cookie = create_auth_cookie($self);
	set_cookie_authed($self, $cookie);
	set_cookie($self, {name => "auth", value => $cookie, "Max-Age" => $self->{authtimeoutsecs}, "Path" => "/"});
}


sub get_ip {
	my $self = shift;
	read_info($self) unless defined($self->{info});
	return $self->{info}->{IP};
}

#since redirect with post data makes browsers ask lame questions about reposting
sub redirect_soft {
	my ($self, $newloc) = @_;
	$self->responsetype(200);
	$self->contenttype("text/html");
	$self->respond("<html><META HTTP-EQUIV=\"Refresh\" CONTENT=\"1;URL=" . $newloc . "\"></html>");
	$self->submit;
}

sub redirect {
	my ($self, $newloc) = @_;
	my $handle;
	open($handle, '>', $self->{response_fn}) or die($self->{failed_handle_msg});
	print { $handle } "HTTP/1.1 307 Moved temporary\r\nLocation: " . $newloc . "\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n307";
	close $handle;
}

sub respond500 {
	my ($self) = @_;
	my $handle;
	open($handle, '>', $self->{response_fn}) or die($self->{failed_handle_msg});
	print { $handle } "HTTP/1.1 500 Wanna fool me?\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nFU";
	close $handle;
}

sub respond404 {
	my ($self) = @_;
	my $handle;
	open($handle, '>', $self->{response_fn}) or die($self->{failed_handle_msg});
	print { $handle } "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n404";
	close $handle;
}

sub responsetype {
	my ($self, $responsenr) = @_;
	if($responsenr == 404 || $responsenr == 500 || $responsenr == 200 || $responsenr == 307) {
		$self->{response_err} = $responsenr;
	} else {
		die("unimplemented responsetype");
	}
}

sub contenttype {
	my $self = shift;
	$self->{response_contenttype} = shift;
}

#expecting hashref as cookie, like:
# { name => "foo", value => "bar", "Max-Age" => 600, "Path" => "/", "Domain" => ".example.com", "HttpOnly" => undef }
#other possible fields: "Expires" => "Wed, 13-Jan-2021 22:23:01 GMT" "Secure" => undef
#set value => "deleted" and/or Max-Age to 0 to delete the cookie
sub set_cookie {
	my ($self, $cookie) = @_;
	push @{$self->{response_cookies}}, $cookie;
}

#if you pass an array, you have to add a \n manually, if required
sub respond {
	my $self = shift;
	my $line;
	die("cannot respond without a responsetype") unless (defined($self->{response_err}));
	while(defined(($line = shift))) {
		push @{$self->{response_arr}}, $line;
		$self->{response_len} += length($line);
	}
}

sub submit {
	my $self = shift;
	my $handle;
	die("cannot respond without a responsetype") unless (defined($self->{response_err}));
	open($handle, '>', $self->{response_fn}) or die($self->{failed_handle_msg});
	if($self->{response_err} == 404) {
		print { $handle } "HTTP/1.1 404 Not found\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n404";
		return;
	} elsif ($self->{response_err} == 500) {
		print { $handle } "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nError";
		return;
	}
	$self->{response_contenttype} = "text/html" unless(defined($self->{response_contenttype}));
	print { $handle } "HTTP/1.1 200 OK\r\nContent-Type: " . $self->{response_contenttype} . "\r\n";
	for my $cookie(@{$self->{response_cookies}}) {
		die("invalid cookie! need name and value") if(!defined($cookie->{name}) || !defined($cookie->{value}));
		my $cc = "Set-Cookie: " . $cookie->{name} . "=" . url_encode($cookie->{value}) . "; ";
		for my $ck(keys %{$cookie}) {
			next if($ck eq "name" || $ck eq "value");
			$cc .= $ck;
			if(defined($cookie->{$ck})) {
				$cc .= "=" . $cookie->{$ck};
			}
			$cc .= "; ";
		}
		$cc .= "\r\n";
		print { $handle } $cc;
	}
	print { $handle } "Content-Length: " . $self->{response_len} . "\r\n\r\n";
	for my $line(@{$self->{response_arr}}) {
		print { $handle } $line;
	}
	close $handle;
}

1;
