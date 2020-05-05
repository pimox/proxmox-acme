package PVE::ACME::DNSChallenge;

use strict;
use warnings;

use Digest::SHA qw(sha256);
use PVE::Tools;

use base qw(PVE::ACME::Challenge);

my $ACME_PATH = '/usr/share/proxmox-acme/proxmox-acme';

sub supported_challenge_types {
    return ["dns-01"];
}

sub type {
    return 'dns';
}

# describe the data schema of the supported plugins
my $plugins = {
    'acmedns' => {},
    'acmeproxy' => {},
    'active24' => {},
    'ad' => {},
    'ali' => {},
    'autodns' => {},
    'aws' => {},
    'azure' => {},
    'cf' => {},
    'clouddns' => {},
    'cloudns' => {},
    'cn' => {},
    'conoha' => {},
    'constellix' => {},
    'cx' => {},
    'cyon' => {},
    'da' => {},
    'ddnss' => {},
    'desec' => {},
    'dgon' => {},
    'dnsimple' => {},
    'do' => {},
    'doapi' => {},
    'domeneshop' => {},
    'dp' => {},
    'dpi' => {},
    'dreamhost' => {},
    'duckdns' => {},
    'durabledns' => {},
    'dyn' => {},
    'dynu' => {},
    'dynv6' => {},
    'easydns' => {},
    'euserv' => {},
    'exoscale' => {},
    'freedns' => {},
    'gandi_livedns' => {},
    'gcloud' => {},
    'gd' => {},
    'gdnsdk' => {},
    'he' => {},
    'hexonet' => {},
    'hostingde' => {},
    'infoblox' => {},
    'internetbs' => {},
    'inwx' => {},
    'ispconfig' => {},
    'jd' => {},
    'kas' => {},
    'kinghost' => {},
    'knot' => {},
    'leaseweb' => {},
    'lexicon' => {},
    'linode' => {},
    'linode_v4' => {},
    'loopia' => {},
    'lua' => {},
    'maradns' => {},
    'me' => {},
    'miab' => {},
    'misaka' => {},
    'myapi' => {},
    'mydevil' => {},
    'mydnsjp' => {},
    'namecheap' => {},
    'namecom' => {},
    'namesilo' => {},
    'nederhost' => {},
    'neodigit' => {},
    'netcup' => {},
    'nic' => {},
    'nsd' => {},
    'nsone' => {},
    'nsupdate' => {},
    'nw' => {},
    'one' => {},
    'online' => {},
    'openprovider' => {},
    'opnsense' => {},
    'ovh' => {
	name => 'OVH',
	fields => {
	    'OVH_END_POINT' => {
		description => "The OVH endpoint",
		default => "ovh-eu",
		optional => 1,
		type => 'string',
	    },
	    'OVH_AK' => {
		description => "The application key.",
		type => 'string',
	    },
	    'OVH_AS' => {
		description => "The application secret.",
		type => 'string',
	    },
	    'OVH_CK' => {
		description => "The consumer key.",
		optional => 1,
		type => 'string',
	    },
	},
    },
    'pdns' => {
	name => 'PowerDNS server',
	fields => {
	    'PDNS_Url' => {
		description => "The PowerDNS API endpoint.",
		type => 'string',
	    },
	    'PDNS_ServerId'=> {
		type => 'string',
	    },
	    'PDNS_Token'=> {
		type => 'string',
	    },
	    'PDNS_Ttl'=> {
		type => 'integer',
	    },
	},
    },
    'pleskxml' => {},
    'pointhq' => {},
    'rackspace' => {},
    'rcode0' => {},
    'regru' => {},
    'schlundtech' => {},
    'selectel' => {},
    'servercow' => {},
    'tele3' => {},
    'ultra' => {},
    'unoeuro' => {},
    'variomedia' => {},
    'vscale' => {},
    'vultr' => {},
    'yandex' => {},
    'zilore' => {},
    'zone' => {},
    'zonomi' => {},
};

sub get_supported_plugins {
    return $plugins;
}

sub properties {
    return {
	api => {
	    description => "API plugin name",
	    type => 'string',
	    enum => [sort keys %$plugins],
	},
	data => {
	    type => 'string',
	    description => 'DNS plugin data. (base64 encoded)',
	},
	'validation-delay' => {
	    type => 'integer',
	    description => 'Extra delay in seconds to wait before requesting validation.'
	        .' Allows to cope with a long TTL of DNS records.',
	    # low default, but our bet is that the acme-challenge domain isn't
	    # cached at all, so it hopefully shouldn't run into TTL issues
	    default => 30,
	    optional => 1,
	    minimum => 0,
	    maximum => 2 * 24 * 60 * 60,
	}
    };
}

sub options {
    return {
	api => {},
	data => { optional => 1 },
	nodes => { optional => 1 },
	disable => { optional => 1 },
	'validation-delay' => { optional => 1 },
    };
}

my $proxmox_acme_command = sub {
    my ($self, $acme, $auth, $data, $action) = @_;

    die "No plugin data for DNSChallenge\n" if !defined($data->{plugin});

    my $alias = $data->{alias};
    my $domain = $auth->{identifier}->{value};

    my $challenge = $self->extract_challenge($auth->{challenges});
    my $key_auth = $acme->key_authorization($challenge->{token});

    my $txtvalue = PVE::ACME::encode(sha256($key_auth));
    my $dnsplugin = $data->{plugin}->{api};
    my $plugin_conf_string = $data->{plugin}->{data};

    # for security reasons, we execute the command as nobody
    # we can't verify that the code of the DNSPlugins are harmless.
    my $cmd = ["setpriv", "--reuid", "nobody", "--regid", "nogroup", "--clear-groups", "--reset-env", "--"];

    # The order of the parameters passed to proxmox-acme is important
    # proxmox-acme <setup|teardown> $plugin <$domain|$alias> $txtvalue [$plugin_conf_string]
    push @$cmd, "/bin/bash", $ACME_PATH, $action, $dnsplugin;
    if ($alias) {
	push @$cmd, $alias;
    } else {
	push @$cmd, $domain;
    }
    my $input = "$txtvalue\n";
    $input .= "$plugin_conf_string\n" if $plugin_conf_string;

    PVE::Tools::run_command($cmd, input => $input);

    $data->{url} = $challenge->{url};

    return $domain;
};

sub setup {
    my ($self, $acme, $auth, $data) = @_;

    my $domain = $proxmox_acme_command->($self, $acme, $auth, $data, 'setup');
    print "Add TXT record: _acme-challenge.$domain\n";

    # FIXME: probe ourself for propagation of TXT record, while not 100%
    # failsafe it's good enough of a heuristic to do away with fixed sleep
    # intervalls - original acme.sh employs that heuristic too.
    my $delay = $data->{'validation-delay'} // 30;
    if ($delay > 0) {
	print "Sleeping $delay seconds to wait for TXT record propagation\n";
	sleep($delay); # don't care for EINTR
    }
}

sub teardown {
    my ($self, $acme, $auth, $data) = @_;

    my $domain = $proxmox_acme_command->($self, $acme, $auth, $data, 'teardown');
    print "Remove TXT record: _acme-challenge.$domain\n";
}

1;
