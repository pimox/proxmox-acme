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

# describe the data schema of the supported plugins, e.g.:
#    'dnsprovider' => {
#	name => 'Full name of Plugin',
#	fields => {
#	    'FOO_API_KEY' => {
#		description => "The API key",
#		default => "none",
#		optional => 1,
#		type => 'string',
#	    },
#	    # ...
#	},
#    },
my $plugins = {
    '1984hosting' => {},
    'acmedns' => {},
    'acmeproxy' => {},
    'active24' => {
	name => 'Active24',
	fields => {
	    'ACTIVE24_Token' => {
		description => "The API key",
		type => 'string',
	    },
	},
    },
    'ad' => {
	name => 'Alwaysdata',
	fields => {
	    'AD_API_KEY' => {
		description => "The API key",
		type => 'string',
	    },
	},
    },
    'ali' => {
	name => 'Alibaba Cloud DNS',
	fields => {
	    'Ali_API' => {
		description => 'The API endpoint',
		default => "https://alidns.aliyuncs.com/",
		type => 'string',
		optional => 1,
	    },
	    'Ali_Key' => {
		description => 'The API Key',
		type => 'string',
	    },
	    'Ali_Secret' => {
		description => 'The API Secret',
		type => 'string',
	    },
	},
    },
    'anx' => {},
    'arvan' => {},
    'autodns' => {},
    'aws' => {
	name => 'Amazon Route53 (AWS)',
	fields => {
	    'AWS_ACCESS_KEY_ID' => {
		name => 'ACCESS_KEY_ID',
		description => 'The AWS access-key ID',
		type => 'string',
	    },
	    'AWS_SECRET_ACCESS_KEY' => {
		name => 'SECRET_ACCESS_KEY',
		description => 'The AWS access-key secret',
		type => 'string',
	    },
	},
    },
    'azure' => {},
    'cf' => {
	name => 'Cloudflare Managed DNS',
	description => 'Either provide global account key and email, or CF API token and Account ID.',
	fields => {
	    'CF_Key' => {
		description => 'The Cloudflare Global API Key',
		type => 'string',
	    },
	    'CF_Email' => {
		description => 'The Cloudflare Account EMail-Address',
		type => 'string',
	    },
	    'CF_Token' => {
		description => 'The new Cloudflare API Token',
		type => 'string',
	    },
	    'CF_Account_ID' => {
		description => 'The new Cloudflare API Account ID',
		type => 'string',
	    },
	    'CF_Zone_ID' => {
		description => 'For Zone restricted API Token',
		type => 'string',
	    },
	},
    },
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
    'df' => {},
    'dgon' => {
	name => 'DigitalOcean DNS',
	fields => {
	    'DO_API_KEY' => {
		description => 'The DigitalOcean API Key',
		type => 'string',
	    },
	},
    },
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
    'edgedns' => {},
    'euserv' => {},
    'exoscale' => {},
    'freedns' => {},
    'gandi_livedns' => {},
    'gcloud' => {},
    'gd' => {
	name => 'GoDaddy',
	fields => {
	    'GD_Key' => {
		description => 'The GoDaddy API Key',
		type => 'string',
	    },
	    'GD_Secret' => {
		description => 'The GoDaddy API Secret',
		type => 'string',
	    },
	},
    },
    'gdnsdk' => {},
    'he' => {},
    'hetzner' => {},
    'hexonet' => {},
    'hostingde' => {},
    'huaweicloud' => {},
    'infoblox' => {},
    'infomaniak' => {},
    'internetbs' => {},
    'inwx' => {
	name => 'INWX',
	fields => {
	    'INWX_User' => {
		description => 'The INWX username',
		type => 'string',
	    },
	    'INWX_Password' => {
		description => 'The INWX password',
		type => 'string',
	    },
	},
    },
    'ispconfig' => {},
    'jd' => {},
    'joker' => {},
    'kappernet' => {},
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
    'netlify' => {},
    'nic' => {},
    'njalla' => {},
    'nm' => {},
    'nsd' => {},
    'nsone' => {},
    'nsupdate' => {},
    'nw' => {},
    'one' => {},
    'online' => {},
    'openprovider' => {},
    'openstack' => {},
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
    'transip' => {},
    'ultra' => {},
    'unoeuro' => {},
    'variomedia' => {},
    'vscale' => {},
    'vultr' => {},
    'world4you' => {},
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

    my $delay = $data->{plugin}->{'validation-delay'} // 30;
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
