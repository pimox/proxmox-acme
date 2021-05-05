PREFIX=/usr
ACMEDIR=${PREFIX}/share/proxmox-acme/
PERLDIR=${PREFIX}/share/perl5

ACME_SOURCES = \
	dnsapi/dns_1984hosting.sh \
	dnsapi/dns_acmedns.sh \
	dnsapi/dns_acmeproxy.sh \
	dnsapi/dns_active24.sh \
	dnsapi/dns_ad.sh \
	dnsapi/dns_ali.sh \
	dnsapi/dns_anx.sh \
	dnsapi/dns_arvan.sh \
	dnsapi/dns_aurora.sh \
	dnsapi/dns_autodns.sh \
	dnsapi/dns_aws.sh \
	dnsapi/dns_azure.sh \
	dnsapi/dns_cf.sh \
	dnsapi/dns_clouddns.sh \
	dnsapi/dns_cloudns.sh \
	dnsapi/dns_cn.sh \
	dnsapi/dns_conoha.sh \
	dnsapi/dns_constellix.sh \
	dnsapi/dns_cx.sh \
	dnsapi/dns_cyon.sh \
	dnsapi/dns_da.sh \
	dnsapi/dns_ddnss.sh \
	dnsapi/dns_desec.sh \
	dnsapi/dns_df.sh \
	dnsapi/dns_dgon.sh \
	dnsapi/dns_dnsimple.sh \
	dnsapi/dns_do.sh \
	dnsapi/dns_doapi.sh \
	dnsapi/dns_domeneshop.sh \
	dnsapi/dns_dp.sh \
	dnsapi/dns_dpi.sh \
	dnsapi/dns_dreamhost.sh \
	dnsapi/dns_duckdns.sh \
	dnsapi/dns_durabledns.sh \
	dnsapi/dns_dyn.sh \
	dnsapi/dns_dynu.sh \
	dnsapi/dns_dynv6.sh \
	dnsapi/dns_easydns.sh \
	dnsapi/dns_edgedns.sh \
	dnsapi/dns_euserv.sh \
	dnsapi/dns_exoscale.sh \
	dnsapi/dns_freedns.sh \
	dnsapi/dns_gandi_livedns.sh \
	dnsapi/dns_gcloud.sh \
	dnsapi/dns_gd.sh \
	dnsapi/dns_gdnsdk.sh \
	dnsapi/dns_he.sh \
	dnsapi/dns_hetzner.sh \
	dnsapi/dns_hexonet.sh \
	dnsapi/dns_hostingde.sh \
	dnsapi/dns_huaweicloud.sh \
	dnsapi/dns_infoblox.sh \
	dnsapi/dns_infomaniak.sh \
	dnsapi/dns_internetbs.sh \
	dnsapi/dns_inwx.sh \
	dnsapi/dns_ionos.sh \
	dnsapi/dns_ispconfig.sh \
	dnsapi/dns_jd.sh \
	dnsapi/dns_joker.sh \
	dnsapi/dns_kappernet.sh \
	dnsapi/dns_kas.sh \
	dnsapi/dns_kinghost.sh \
	dnsapi/dns_knot.sh \
	dnsapi/dns_leaseweb.sh \
	dnsapi/dns_lexicon.sh \
	dnsapi/dns_linode.sh \
	dnsapi/dns_linode_v4.sh \
	dnsapi/dns_loopia.sh \
	dnsapi/dns_lua.sh \
	dnsapi/dns_maradns.sh \
	dnsapi/dns_me.sh \
	dnsapi/dns_miab.sh \
	dnsapi/dns_misaka.sh \
	dnsapi/dns_myapi.sh \
	dnsapi/dns_mydevil.sh \
	dnsapi/dns_mydnsjp.sh \
	dnsapi/dns_namecheap.sh \
	dnsapi/dns_namecom.sh \
	dnsapi/dns_namesilo.sh \
	dnsapi/dns_nederhost.sh \
	dnsapi/dns_neodigit.sh \
	dnsapi/dns_netcup.sh \
	dnsapi/dns_netlify.sh \
	dnsapi/dns_nic.sh \
	dnsapi/dns_njalla.sh \
	dnsapi/dns_nm.sh \
	dnsapi/dns_nsd.sh \
	dnsapi/dns_nsone.sh \
	dnsapi/dns_nsupdate.sh \
	dnsapi/dns_nw.sh \
	dnsapi/dns_one.sh \
	dnsapi/dns_online.sh \
	dnsapi/dns_openprovider.sh \
	dnsapi/dns_openstack.sh \
	dnsapi/dns_opnsense.sh \
	dnsapi/dns_ovh.sh \
	dnsapi/dns_pdns.sh \
	dnsapi/dns_pleskxml.sh \
	dnsapi/dns_pointhq.sh \
	dnsapi/dns_porkbun.sh \
	dnsapi/dns_rackcorp.sh \
	dnsapi/dns_rackspace.sh \
	dnsapi/dns_rcode0.sh \
	dnsapi/dns_regru.sh \
	dnsapi/dns_scaleway.sh \
	dnsapi/dns_schlundtech.sh \
	dnsapi/dns_selectel.sh \
	dnsapi/dns_servercow.sh \
	dnsapi/dns_simply.sh \
	dnsapi/dns_tele3.sh \
	dnsapi/dns_transip.sh \
	dnsapi/dns_ultra.sh \
	dnsapi/dns_unoeuro.sh \
	dnsapi/dns_variomedia.sh \
	dnsapi/dns_vscale.sh \
	dnsapi/dns_vultr.sh \
	dnsapi/dns_websupport.sh \
	dnsapi/dns_world4you.sh \
	dnsapi/dns_yandex.sh \
	dnsapi/dns_zilore.sh \
	dnsapi/dns_zone.sh \
	dnsapi/dns_zonomi.sh \

LIB_SOURCES = \
	ACME.pm \
	ACME/Challenge.pm \
	ACME/DNSChallenge.pm \
	ACME/StandAlone.pm \

all:

.PHONY: install
install:
	install -D -m 0744 proxmox-acme ${DESTDIR}${ACMEDIR}/proxmox-acme
	for f in ${ACME_SOURCES}; do install -D -m 0644 acme.sh/$$f ${DESTDIR}${ACMEDIR}/$$f; done
	install -d -m 0755 ${DESTDIR}${PERLDIR}/PVE
	install -d -m 0755 ${DESTDIR}${PERLDIR}/PVE/ACME
	for f in ${LIB_SOURCES}; do install -D -m 0644 PVE/$$f ${DESTDIR}${PERLDIR}/PVE/$$f; done

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: clean
clean:
	rm -rf *~

.PHONY: distclean
distclean: clean
