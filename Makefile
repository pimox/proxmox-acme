include /usr/share/dpkg/pkg-info.mk

SRC=libproxmox-acme

BUILDDIR ?= ${SRC}-${DEB_VERSION_UPSTREAM}
GITVERSION:=$(shell git rev-parse HEAD)

DEB_PERL=libproxmox-acme-perl_${DEB_VERSION_UPSTREAM_REVISION}_all.deb
DEB_ACME_PLUGS=libproxmox-acme-plugins_${DEB_VERSION_UPSTREAM_REVISION}_all.deb
DEBS=${DEB_PERL} ${DEB_ACME_PLUGS}

DSC=${SRC}_${DEB_VERSION_UPSTREAM_REVISION}.dsc

ACME_SUBMODULE="src/acme.sh"

all: $(DEB)

.PHONY: submodule
submodule:
	test -d ${ACME_SUBMODULE}/README.md || git submodule update --init --recursive

${BUILDDIR}: src debian submodule
	rm -rf ${BUILDDIR}.tmp
	cp -a src ${BUILDDIR}.tmp
	cp -a debian ${BUILDDIR}.tmp/
	echo "git clone git://git.proxmox.com/git/proxmox-acme\\ngit checkout ${GITVERSION}" > ${BUILDDIR}.tmp/debian/SOURCE
	mv ${BUILDDIR}.tmp ${BUILDDIR}

.PHONY: deb
deb: ${DEBS}
${DEBS}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -b -us -uc
	lintian ${DEBS}

.PHONY: dsc
dsc: ${DSC}
${DSC}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -S -us -uc -d
	lintian ${DSC}

dinstall: ${DEBS}
	dpkg -i ${DEBS}

.PHONY: clean
clean:
	rm -rf ${SRC}-*/ ${BUILDDIR}.tmp *.deb *.buildinfo *.changes *.dsc *.tar.?z

.PHONY: upload
upload: ${DEBS}
	tar cf - ${DEBS}|ssh -X repoman@repo.proxmox.com -- upload --product pve,pmg --dist buster --arch ${DEB_BUILD_ARCH}
	tar cf - ${DEB_ACME_PLUGS}|ssh -X repoman@repo.proxmox.com -- upload --product pbs --dist buster --arch ${DEB_BUILD_ARCH}
