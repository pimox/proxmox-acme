package PVE::ACME::Challenge;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::SectionConfig);

my $defaultData = {
    additionalProperties => 0,
    propertyList => {
	id => {
	    description => "ACME Plugin ID name",
	    type => 'string',
	},
	type => {
	    description => "ACME challenge type.",
	    type => 'string',
	},
	disable => {
	    description => "Flag to disable the config.",
	    type => 'boolean',
	    optional => 1,
	},
	nodes => get_standard_option('pve-node-list', { optional => 1 }),
    },
};

sub private {
    return $defaultData;
}

sub parse_config {
    my ($class, $filename, $raw) = @_;

    my $cfg = $class->SUPER::parse_config($filename, $raw);
    my $ids = $cfg->{ids};

    # make sure we have a standalone plugin definition as fallback!
    if (!$ids->{standalone} || $ids->{standalone}->{type} ne 'standalone') {
	$ids->{standalone} = {
	    type => 'standalone',
	};
    }

    return $cfg;
}

sub supported_challenge_types {
    return {};
}

sub extract_challenge {
    my ($self, $challenges, $c_type) = @_;

    die "no challenges defined\n" if !$challenges;
    die "no challenge type is defined \n" if !$c_type;

    my $tmp_challenges = [ grep {$_->{type} eq $c_type} @$challenges ];
    die "no $c_type challenge defined in authorization\n"
	if ! scalar $tmp_challenges;

    my $challenge = $tmp_challenges->[0];

    return $challenge;
}

sub get_subplugins {
    return [];
}

sub setup {
    my ($class, $acme, $authorization) = @_;

    die "implement me\n";
}

sub teardown {
    my ($self) = @_;

    die "implement me\n";
}

1;
