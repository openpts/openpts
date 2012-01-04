#
# Makefile.am
#
# This file is part of the OpenPTS project.
#
# The Initial Developer of the Original Code is International
# Business Machines Corporation. Portions created by IBM
# Corporation are Copyright (C) 2010 International Business
# Machines Corporation. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Common Public License as published by
# IBM Corporation; either version 1 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# Common Public License for more details.
#
# You should have received a copy of the Common Public License
# along with this program; if not, a copy can be viewed at
# http://www.opensource.org/licenses/cpl1.0.php.
#

#SUBDIRS		= 	m4  	\
#			include \
#			lib	\
#			src	\
#			tests	\
#			po \
#			man
#
ACLOCAL_AMFLAGS = -I m4
#
#EXTRA_DIST = LICENSE

SUBDIRS = m4 po include src doc models man

#
# Symlink to openpts-version dir
#

../$(PACKAGE)-$(PACKAGE_VERSION):
	ln -s $(PWD) ../$(PACKAGE)-$(PACKAGE_VERSION)

#
# tar ball
#

tgz:  ../$(PACKAGE)-$(PACKAGE_VERSION)
	cd ..; tar --exclude=.git --exclude=.svn --exclude=bin --exclude=.project -zcvf $(PACKAGE)-$(PACKAGE_VERSION).tar.gz $(PACKAGE)-$(PACKAGE_VERSION)/*

#
# Build RPM Package
# ./bootstrap.sh;./configure; make rpmbuild-ba
#
RPMDIR=$(HOME)/rpmbuild


rpmbuild-ba: ../$(PACKAGE)-$(PACKAGE_VERSION)
	rm -f  $(RPMDIR)/SOURCES/$(PACKAGE)-$(PACKAGE_VERSION).tar.gz 
	make clean
	cd ..; tar --exclude=.git --exclude=bin --exclude=tests --exclude=.project -zcvf $(RPMDIR)/SOURCES/$(PACKAGE)-$(PACKAGE_VERSION).tar.gz $(PACKAGE)-$(PACKAGE_VERSION)/*
	cd ..; rpmbuild -ba $(PACKAGE)-$(PACKAGE_VERSION)/dist/$(PACKAGE).spec


#
# Build DEB Package
# ./bootstrap.sh;./configure; make dpkg-buildpackage
# dpkg --contents ../openpts_0.2.0_i386.deb

debian:
	ln -s $(PWD)/ChangeLog dist/debian/changelog
	ln -s $(PWD)/LICENSE dist/debian/copyright
	ln -s $(PWD)/README dist/debian/docs
	ln -s $(PWD)/dist/debian debian

dpkg-buildpackage: debian
	chmod +x debian/rules
	-dpkg-buildpackage -tc -uc -b
	@echo "make dpkg-buildpackage - done" 
	ls -l ../*openpts*deb

debian-clean:
	rm dist/debian/changelog
	rm dist/debian/copyright
	rm dist/debian/docs
	rm debian

