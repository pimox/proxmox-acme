package PVE::ACME::DNSChallenge;

use strict;
use warnings;

use Digest::SHA qw(sha256);
use PVE::Tools;

use base qw(PVE::ACME::Challenge);

my $ACME_PATH = '/usr/share/proxmox-acme/proxmox-acme';

sub supported_challenge_types {
    return { 'dns-01' => 1 };
}

sub type {
    return 'dns';
}

my $api_name_list = [
    'acmedns',
    'acmeproxy',
    'active24',
    'ad',
    'ali',
    'autodns',
    'aws',
    'azure',
    'cf',
    'clouddns',
    'cloudns',
    'cn',
    'conoha',
    'constellix',
    'cx',
    'cyon',
    'da',
    'ddnss',
    'desec',
    'dgon',
    'dnsimple',
    'do',
    'doapi',
    'domeneshop',
    'dp',
    'dpi',
    'dreamhost',
    'duckdns',
    'durabledns',
    'dyn',
    'dynu',
    'dynv6',
    'easydns',
    'euserv',
    'exoscale',
    'freedns',
    'gandi_livedns',
    'gcloud',
    'gd',
    'gdnsdk',
    'he',
    'hexonet',
    'hostingde',
    'infoblox',
    'internetbs',
    'inwx',
    'ispconfig',
    'jd',
    'kas',
    'kinghost',
    'knot',
    'leaseweb',
    'lexicon',
    'linode',
    'linode_v4',
    'loopia',
    'lua',
    'maradns',
    'me',
    'miab',
    'misaka',
    'myapi',
    'mydevil',
    'mydnsjp',
    'namecheap',
    'namecom',
    'namesilo',
    'nederhost',
    'neodigit',
    'netcup',
    'nic',
    'nsd',
    'nsone',
    'nsupdate',
    'nw',
    'one',
    'online',
    'openprovider',
    'opnsense',
    'ovh',
    'pdns',
    'pleskxml',
    'pointhq',
    'rackspace',
    'rcode0',
    'regru',
    'schlundtech',
    'selectel',
    'servercow',
    'tele3',
    'ultra',
    'unoeuro',
    'variomedia',
    'vscale',
    'vultr',
    'yandex',
    'zilore',
    'zone',
    'zonomi',
];

sub properties {
    return {
	api => {
	    description => "API plugin name",
	    type => 'string',
	    enum => $api_name_list,
	},
	data => {
	    type => 'string',
	    description => 'DNS plugin data.',
	},
    };
}

sub options {
    return {
	api => {},
	data => { optional => 1 },
	nodes => { optional => 1 },
	disable => { optional => 1 },
    };
}

my $outfunc = sub {
    my $line = shift;
    print "$line\n";
};

sub extract_challenge {
    my ($self, $challenge) = @_;

    return PVE::ACME::Challenge->extract_challenge($challenge, 'dns-01');
}
    
sub get_subplugins {
    return $api_name_list;
}

# The order of the parameters passed to proxmox-acme is important
# proxmox-acme setup $plugin [$domain|$alias] $txtvalue $plugin_conf_string
sub setup {
    my ($self, $data) = @_;

    die "No plugin data for DNSChallenge\n" if !defined($data->{plugin});
    my $domain = $data->{plugin}->{alias} ? $data->{plugin}->{alias} : $data->{domain};
    my $txtvalue = PVE::ACME::encode(sha256($data->{key_authorization}));
    my $dnsplugin = $data->{plugin}->{api};
    my $plugin_conf_string = $data->{plugin}->{data};

    # for security reasons, we execute the command as nobody
    # we can't verify that the code of the DNSPlugins are harmless.
    my $cmd = ["setpriv", "--reuid", "nobody", "--regid", "nogroup", "--clear-groups", "--"];
    push @$cmd, "/usr/bin/bash", $ACME_PATH, "setup", $dnsplugin, $domain;
    push @$cmd,	$txtvalue, $plugin_conf_string;

    PVE::Tools::run_command($cmd, outfunc => $outfunc);
    print "Add TXT record: _acme-challenge.$domain\n";
}

# The order of the parameters passed to proxmox-acme is important
# proxmox-acme teardown $plugin [$domain|$alias] $txtvalue $plugin_conf_string
sub teardown {
    my ($self, $data) = @_;

    die "No plugin data for DNSChallenge\n" if !defined($data->{plugin});
    my $domain = $data->{plugin}->{alias} ? $data->{plugin}->{alias} : $data->{domain};
    my $txtvalue = PVE::ACME::encode(sha256($data->{key_authorization}));
    my $dnsplugin = $data->{plugin}->{api};
    my $plugin_conf_string = $data->{plugin}->{data};
    
    # for security reasons, we execute the command as nobody
    # we can't verify that the code of the DNSPlugins are harmless.
    my $cmd = ["setpriv", "--reuid", "nobody", "--regid", "nogroup", "--clear-groups", "--"];
    push @$cmd, "/usr/bin/bash", "$ACME_PATH", "teardown",  $dnsplugin, $domain ;
    push @$cmd, $txtvalue, $plugin_conf_string;
    PVE::Tools::run_command($cmd, outfunc => $outfunc);
    print "Remove TXT record: _acme-challenge.$domain\n";
}

1;
