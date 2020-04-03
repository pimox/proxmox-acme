PREFIX=/usr
ACMEDIR=${PREFIX}/share/proxmox-acme/

ACME_SOURCES = \
	dnsapi/dns_nsone.sh \
	dnsapi/dns_cf.sh \
	dnsapi/dns_linode.sh \
	dnsapi/dns_dnsimple.sh \
	dnsapi/dns_lexicon.sh \
	dnsapi/dns_da.sh \
	dnsapi/dns_desec.sh \
	dnsapi/dns_he.sh \
	dnsapi/dns_doapi.sh \
	dnsapi/dns_pdns.sh \
	dnsapi/dns_yandex.sh \
	dnsapi/dns_nic.sh \
	dnsapi/dns_conoha.sh \
	dnsapi/dns_schlundtech.sh \
	dnsapi/dns_do.sh \
	dnsapi/dns_autodns.sh \
	dnsapi/dns_tele3.sh \
	dnsapi/dns_gd.sh \
	dnsapi/dns_exoscale.sh \
	dnsapi/dns_kas.sh \
	dnsapi/dns_easydns.sh \
	dnsapi/dns_pleskxml.sh \
	dnsapi/dns_variomedia.sh \
	dnsapi/dns_duckdns.sh \
	dnsapi/dns_kinghost.sh \
	dnsapi/dns_myapi.sh \
	dnsapi/dns_nw.sh \
	dnsapi/dns_misaka.sh \
	dnsapi/dns_one.sh \
	dnsapi/dns_mydevil.sh \
	dnsapi/dns_acmedns.sh \
	dnsapi/dns_gandi_livedns.sh \
	dnsapi/dns_dgon.sh \
	dnsapi/dns_nsd.sh \
	dnsapi/dns_selectel.sh \
	dnsapi/dns_linode_v4.sh \
	dnsapi/dns_hostingde.sh \
	dnsapi/dns_freedns.sh \
	dnsapi/dns_opnsense.sh \
	dnsapi/dns_servercow.sh \
	dnsapi/dns_hexonet.sh \
	dnsapi/dns_aws.sh \
	dnsapi/dns_dyn.sh \
	dnsapi/dns_leaseweb.sh \
	dnsapi/dns_online.sh \
	dnsapi/dns_gcloud.sh \
	dnsapi/dns_active24.sh \
	dnsapi/dns_jd.sh \
	dnsapi/dns_internetbs.sh \
	dnsapi/dns_vscale.sh \
	dnsapi/dns_durabledns.sh \
	dnsapi/dns_dynv6.sh \
	dnsapi/dns_openprovider.sh \
	dnsapi/dns_nsupdate.sh \
	dnsapi/dns_inwx.sh \
	dnsapi/dns_namecom.sh \
	dnsapi/dns_infoblox.sh \
	dnsapi/dns_ultra.sh \
	dnsapi/dns_unoeuro.sh \
	dnsapi/dns_cloudns.sh \
	dnsapi/dns_ovh.sh \
	dnsapi/dns_cn.sh \
	dnsapi/dns_azure.sh \
	dnsapi/dns_namecheap.sh \
	dnsapi/dns_vultr.sh \
	dnsapi/dns_acmeproxy.sh \
	dnsapi/dns_ddnss.sh \
	dnsapi/dns_maradns.sh \
	dnsapi/dns_cx.sh \
	dnsapi/dns_dreamhost.sh \
	dnsapi/dns_ispconfig.sh \
	dnsapi/dns_nederhost.sh \
	dnsapi/dns_loopia.sh \
	dnsapi/dns_ad.sh \
	dnsapi/dns_cyon.sh \
	dnsapi/dns_ali.sh \
	dnsapi/dns_netcup.sh \
	dnsapi/dns_knot.sh \
	dnsapi/dns_zone.sh \
	dnsapi/dns_me.sh \
	dnsapi/dns_namesilo.sh \
	dnsapi/dns_pointhq.sh \
	dnsapi/dns_gdnsdk.sh \
	dnsapi/dns_zilore.sh \
	dnsapi/dns_domen.sh \op.sh \
	dnsapi/dns_miab.sh \
	dnsapi/dns_lua.sh \
	dnsapi/dns_rcode0.sh \
	dnsapi/dns_constellix.sh \
	dnsapi/dns_dpi.sh \
	dnsapi/dns_dynu.sh \
	dnsapi/dns_dp.sh \
	dnsapi/dns_euserv.sh \
	dnsapi/dns_zonomi.sh \
	dnsapi/dns_rackspace.sh \
	dnsapi/dns_regru.sh \
	dnsapi/dns_clouddns.sh \
	dnsapi/dns_neodigit.sh \
	dnsapi/dns_mydnsjp.sh \

all:

.PHONY: install
install:
	install -D -m 0744 proxmox-acme ${DESTDIR}${ACMEDIR}/proxmox-acme
	for i in ${ACME_SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${ACMEDIR}/$$i; done

.PHONY: clean
clean:
	rm -rf *~

.PHONY: distclean
distclean: clean
