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
#
# 1) API Document by doxgen (HTML)
#
#    make lldd
#    firefox apidoc_html/index.html
#
# 2) Design Document
#
#    cd ../models
#    make png
#    cd ../doc 
#    make hldd
#    evince design.pdf
#
# 3) User's guide
#
#    make ug
#    evince userguide.pdf
#
 
AUTOMAKE_OPTIONS=foreign no-dependencies

CLEANFILES = design.aux design.log design.pdf design.toc

# default target - none
all:

clean:
	rm -rf ./images
	rm -rf ./apidoc_html
	rm -rf ./apidoc_latex
	rm -f *~
	rm -f *.aux
	rm -f *.log
	rm -f *.pdf
	rm -f *.toc



#####################################
# High level design document 
#####################################

hldd: design.pdf

design.dvi: design.tex \
TNC_Architecture_1.bb  TNC_Architecture_2.bb  TNC_Architecture_3.bb \
OpenPTS_fig1.bb OpenPTS_fig2.bb OpenPTS_fig3.bb OpenPTS_fig4.bb OpenPTS_fig5.bb \
OpenPTS_fig_standalone.bb OpenPTS_fig_tnc.bb \
OpenPTS_fig_iidb.bb OpenPTS_fig_aide.bb \
../models/bios_pcr0.bb ../models/bios_pcr1.bb ../models/bios_pcr2.bb ../models/bios_pcr3.bb \
../models/bios_pcr4.bb ../models/bios_pcr5.bb ../models/bios_pcr6.bb ../models/bios_pcr7.bb \
../models/grub_pcr4.bb ../models/grub_pcr5.bb ../models/grub_pcr8.bb

# Somehow Fedora12 can't include png. No error on Ubuntu.
# Error is (./TNC_Architecture_2.png<?>Error: /syntaxerror in (binary token, type=137)
# 


ug: userguide.pdf

userguide.dvi: userguide_uc1.tex userguide_cmd.tex userguide_platform.tex userguide_build.tex  userguide_config.tex

SUFFIXES = .tex .dvi .png

# RHRL6
# yum install tetex*
# platex->latex
# dvipdfm -> dvipdfmx
.tex.dvi:
	latex $<
	latex $<

.dvi.pdf:
	dvipdfmx $<

.png.bb:
	@if [ -f /usr/bin/ebbx ]; then \
	/usr/bin/ebbx $<; \
	else \
	/usr/bin/ebb $<; \
	fi

#####################################
# Operation flow
#####################################
operationflow.png: operationflow.dot
	dot -Tpng operationflow.dot -o operationflow.png

#####################################
# Low level (API) design document 
#####################################
#
# doxygen 
# src -> html and pdf
#

lldd: refman.html 
# refman.pdf

refman.html: apidoc_html/index.html
#refman.pdf:  apidoc_latex/refman.pdf

images:
	-mkdir images

images/bios_pcr0.png: images ../models/bios_pcr0.png
	echo "RUN cd ../models; make png"
	cp ../models/*png images/

apidoc_html/index.html: FORCE images/bios_pcr0.png
	doxygen doxygen.conf

#apidoc_latex/refman.pdf: apidoc_html/index.html
#	cd apidoc_latex; make

FORCE:


