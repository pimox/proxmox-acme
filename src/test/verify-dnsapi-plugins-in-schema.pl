#!/usr/bin/perl

use strict;
use warnings;

use lib '../';

use JSON;

use PVE::Tools qw(dir_glob_foreach file_get_contents);

my $dnsapi_path = '../acme.sh/dnsapi';

die "cannot find dnsapi path '$dnsapi_path'!\n" if ! -d $dnsapi_path;

my $acmesh_plugins = [];
dir_glob_foreach($dnsapi_path, qr/dns_(\S+)\.sh/, sub {
    my ($file, $provider) = @_;
    push @$acmesh_plugins, $provider;
});

my $DNS_API_CHALLENGE_SCHEMA_FN = '../dns-challenge-schema.json';
my $defined_plugins = from_json(PVE::Tools::file_get_contents($DNS_API_CHALLENGE_SCHEMA_FN));

my $ok = 1;
# first check for missing ones, delete from hash so we can easily see if a plug got removed/renamed
my $printed_missing = 0;
for my $provider (sort @$acmesh_plugins) {
    my $schema = delete $defined_plugins->{$provider};
    if (!defined($schema)) {
	print STDERR "missing (also adapt makefile!):\n" if !$printed_missing;
	print STDERR "    '$provider' => {},\n";
	$printed_missing = 1;
	$ok = 0;
    }
}

my $printed_extra = 0;
for my $provider (sort keys %$defined_plugins) {
    print STDERR "extra:\n" if !$printed_extra;
    print STDERR "    $provider\n";
    $printed_extra = 1;
    $ok = 0;
}

die "schema not in sync with available plugins!\n" if !$ok;

print STDERR "OK: DNS challenge schema in sync with available plugins.\n";
exit(0);
