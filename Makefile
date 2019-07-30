name := pivauth
version := $(shell awk '/^%define version / {print $$3}' $(name).spec)
release := $(shell awk '/^%define release / {print $$3}' $(name).spec)
vname := $(name)-$(version)
tempdir := $(shell mktemp -d)
tarball := $(tempdir)/$(vname).tar.gz
rpm := $(vname)-$(release).x86_64.rpm
rpmbuild_opts += --define "_sourcedir $(tempdir)"
rpmbuild_opts += --clean

all: rpm
tarball: $(tarball)
rpm: $(rpm)

$(tarball):
	tar -czf $(tarball) --exclude ".git" --exclude "Makefile" --exclude "Diagram" --transform='s/^\./pivauth-$(version)/' .

$(rpm): $(tarball)
	rpmbuild $(rpmbuild_opts) -bb $(name).spec
	echo "$(rpm) created."
	rm -rf $(tempdir)
