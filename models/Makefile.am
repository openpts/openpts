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

AUTOMAKE_OPTIONS=foreign no-dependencies

CLEANFILES = *.dot *.png *.dot2

# default target - none
all:

#####################################
# UML to PNG
#####################################

png: bios_png uefi_png grub_png ima_png openpts_png tboot_png ptsc_png

bios_png: \
bios_pcr0.png bios_pcr1.png bios_pcr2.png bios_pcr3.png \
bios_pcr4.png bios_pcr5.png bios_pcr6.png bios_pcr7.png

uefi_png: \
uefi_pcr0.png uefi_pcr1.png uefi_pcr2.png uefi_pcr3.png \
uefi_pcr4.png uefi_pcr5.png uefi_pcr6.png uefi_pcr7.png

grub_png: \
grub_pcr4.png grub_pcr5.png grub_pcr8.png grub_livecd_pcr4.png 

tboot_png: \
tboot_pcr17.png tboot_pcr18.png tboot_pcr19.png

ima_png: \
ima_rhel6_pcr10.png

ptsc_png: \
ptsc_pcr11.png


SUFFIXES = .uml .dot .dot2 .png

.uml.dot:
	../src/uml2dot -o $@ $<

.dot.dot2:
	cat $< | sed -e "s/, digest/\\\\ndigest/g" > $@

.dot2.png:
	dot -Tpng $< -o $@

# EOF
