package PVE::ACME::StandAlone;

use strict;
use warnings;

use HTTP::Daemon;
use HTTP::Response;

use base qw(PVE::ACME::Challenge);

sub supported_challenge_types {
    return { 'http-01' => 1 };
}

sub type {
    return 'standalone';
}

sub properties {
    return {};
}

sub options {
    return {
	nodes => { optional => 1 },
	disable => { optional => 1 },
    };
}

sub extract_challenge {
    my ($self, $challenge) = @_;

    return PVE::ACME::Challenge->extract_challenge($challenge, 'http-01');
}

sub get_subplugins {
    return [];
}

sub setup {
    my ($class, $data) = @_;

    print "Setting up webserver\n";

    my $key_auth = $data->{key_authorization};

    my $server = HTTP::Daemon->new(
	LocalPort => 80,
	ReuseAddr => 1,
	) or die "Failed to initialize HTTP daemon\n";
    my $pid = fork() // die "Failed to fork HTTP daemon - $!\n";
    if ($pid) {
	$data->{server} = $server;
	$data->{pid} = $pid;
    } else {
	while (my $c = $server->accept()) {
	    while (my $r = $c->get_request()) {
		if ($r->method() eq 'GET' and
		    $r->uri->path eq "/.well-known/acme-challenge/$data->{token}") {
		    my $resp = HTTP::Response->new(200, 'OK', undef, $key_auth);
		    $resp->request($r);
		    $c->send_response($resp);
		} else {
		    $c->send_error(404, 'Not found.')
		}
	    }
	    $c->close();
	    $c = undef;
	}
    }
}

sub teardown {
    my ($self, $data) = @_;

    eval { $data->{server}->close() };
    kill('KILL', $data->{pid});
    waitpid($data->{pid}, 0);
}

1;
