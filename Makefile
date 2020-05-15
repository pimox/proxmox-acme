include /usr/share/dpkg/pkg-info.mk

PACKAGE=libproxmox-acme-perl

BUILDDIR ?= ${PACKAGE}-${DEB_VERSION_UPSTREAM}
GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_all.deb
DSC=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}.dsc

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
deb: ${DEB}
${DEB}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

.PHONY: dsc
dsc: ${DSC}
${DSC}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -S -us -uc -d
	lintian ${DSC}

dinstall: ${DEB}
	dpkg -i ${DEB}

.PHONY: clean
clean:
	rm -rf ${PACKAGE}-*/ ${BUILDDIR}.tmp *.deb *.buildinfo *.changes *.dsc *.tar.?z

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB}|ssh -X repoman@repo.proxmox.com -- upload --product pve,pmg --dist buster --arch ${DEB_BUILD_ARCH}
