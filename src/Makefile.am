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

RELEASE = "0.0.2.6"

# Gettext support
localedir = $(datadir)/locale


AM_CPPFLAGS = -I$(top_srcdir)/include $(LIBXML2_CFLAGS) $(TSS_CFLAGS) -I../include -DLOCALEDIR=\"$(localedir)\"
AM_LDFLAGS = $(LIBXML2_LIBS) $(LIBCRYPTO_LIBS) $(TSS_LIBS) -lopenpts
# $(LIBINTL) -lopenpts

if HAVE_LIBUUID
AM_CPPFLAGS += $(LIBUUID_CFLAGS)
AM_LDFLAGS  += $(LIBUUID_LIBS)
endif


sbin_PROGRAMS = ptsc
bin_PROGRAMS = openpts uml2dot rm2dot ir2text
# AIX
# ptsevt ptsevtd

#
# Common Library
#
lib_LTLIBRARIES = libopenpts.la
libopenpts_la_LDFLAGS = -release $(RELEASE)
libopenpts_la_SOURCES = verifier.c ifm.c iml.c ir.c base64.c tpm.c ctx.c \
conf.c uml.c fsm.c rm.c log.c action.c prop.c policy.c tss.c nonce.c smbios.c \
misc.c snapshot.c reason.c uuid.c collector.c ssh.c target.c

#ptsc_SOURCES = ptsc.c log.c
ptsc_CFLAGS = $(AM_CFLAGS)
ptsc_LDFLAGS = $(AM_LDFLAGS)
#ptsc_SOURCES = ptsc.c verifier.c ifm.c iml.c ir.c base64.c tpm.c ctx.c \
#conf.c uml.c fsm.c rm.c log.c action.c prop.c policy.c tss.c nonce.c smbios.c \
#misc.c snapshot.c reason.c uuid.c collector.c ssh.c

ptsc_SOURCES = ptsc.c

#ptscd_SOURCES =	ptscd.c verifier.c ifm.c iml.c ir.c base64.c tpm.c ctx.c \
#conf.c uml.c fsm.c rm.c log.c action.c prop.c policy.c tss.c nonce.c smbios.c \
#misc.c snapshot.c reason.c uuid.c collector.c ssh.c
openpts_CFLAGS = $(AM_CFLAGS)
openpts_LDFLAGS = $(AM_LDFLAGS)
openpts_SOURCES = openpts.c

#verifier.c ifm.c iml.c ir.c base64.c tpm.c ctx.c \
#conf.c uml.c fsm.c rm.c log.c action.c prop.c policy.c nonce.c tss.c misc.c \
#snapshot.c reason.c uuid.c ssh.c


# TODO do not call the ctx?
uml2dot_CFLAGS = $(AM_CFLAGS)
uml2dot_LDFLAGS = $(AM_LDFLAGS)
uml2dot_SOURCES = uml2dot.c


##uml.c fsm.c iml.c tpm.c base64.c action.c prop.c \
#policy.c ctx.c nonce.c misc.c tss.c rm.c ir.c snapshot.c conf.c log.c reason.c \
#uuid.c ssh.c

rm2dot_CFLAGS = $(AM_CFLAGS)
rm2dot_LDFLAGS = $(AM_LDFLAGS)
rm2dot_SOURCES = rm2dot.c


#uml.c fsm.c iml.c tpm.c base64.c action.c prop.c \
#policy.c ctx.c nonce.c misc.c rm.c ir.c tss.c snapshot.c conf.c log.c reason.c \
#uuid.c ssh.c

ir2text_CFLAGS = $(AM_CFLAGS)
ir2text_LDFLAGS = $(AM_LDFLAGS)
ir2text_SOURCES = ir2text.c

#base64.c log.c

# AIX
#ptsevt_CFLAGS = $(AM_CFLAGS)
#ptsevt_LDFLAGS = $(AM_LDFLAGS)
#ptsevt_SOURCES = ptsevt.c

#ptsevtd_CFLAGS = $(AM_CFLAGS)
#ptsevtd_LDFLAGS = $(AM_LDFLAGS) -lrt
#ptsevtd_SOURCES = ptsevtd.c


if HAVE_LIBUUID
#ptscd_SOURCES += uuid_libuuid.c
#ptsc_SOURCES += uuid_libuuid.c
#openpts_SOURCES += uuid_libuuid.c
#uml2dot_SOURCES += uuid_libuuid.c
#rm2dot_SOURCES += uuid_libuuid.c

libopenpts_la_SOURCES +=  uuid_libuuid.c

AM_CPPFLAGS += -DCONFIG_LIBUUID
else
# libc AIX, FreeBSD
#ptscd_SOURCES += uuid_libc.c
#ptsc_SOURCES += uuid_libc.c
#openpts_SOURCES += uuid_libc.c
#uml2dot_SOURCES += uuid_libc.c
#rm2dot_SOURCES += uuid_libc.c
libopenpts_la_SOURCES +=  uuid_libc.c
endif


if OPENPTS_BUILD_TSS
AM_CPPFLAGS += -DCONFIG_TSS

iml2text_CFLAGS = $(AM_CFLAGS)
iml2text_LDFLAGS = $(AM_LDFLAGS)
iml2text_SOURCES = iml2text.c

#misc.c log.c base64.c

tpm_createkey_SOURCE = tpm_createkey.c
#tss.c log.c
tpm_createkey_CFLAGS = $(AM_CFLAGS)


tpm_readpcr_CFLAGS = $(AM_CFLAGS)
tpm_readpcr_LDFLAGS = $(AM_LDFLAGS)
tpm_readpcr_SOURCE = tpm_readpcr.c

tpm_extendpcr_CFLAGS = $(AM_CFLAGS)
tpm_extendpcr_LDFLAGS = $(AM_LDFLAGS)
tpm_extendpcr_SOURCE = tpm_extendpcr.c

bin_PROGRAMS += tpm_createkey iml2text tpm_readpcr tpm_extendpcr
else
AM_CPPFLAGS += -DCONFIG_NO_TSS
endif



if OPENPTS_BUILD_LIBTNC
lib_LTLIBRARIES += libopenpts_imc.la libopenpts_imv.la

libopenpts_imc_la_SOURCES = imc.c
libopenpts_imc_la_CFLAGS = $(AM_CFLAGS) -I../include/tnc
libopenpts_imc_la_LDFLAGS = -release $(RELEASE)
libopenpts_imc_la_LIBADD = $(AM_LDFLAGS) 

libopenpts_imv_la_SOURCES = imv.c
libopenpts_imv_la_CFLAGS = $(AM_CFLAGS) -I../include/tnc
libopenpts_imv_la_LDFLAGS = -release $(RELEASE)
libopenpts_imv_la_LIBADD = $(AM_LDFLAGS) 

else
AM_CPPFLAGS += -DCONFIG_NO_LIBTNC
endif


if OPENPTS_BUILD_AIDE
AM_CPPFLAGS += -DCONFIG_AIDE
bin_PROGRAMS += iml2aide
#ptscd_SOURCES += aide.c
#ptsc_SOURCES += aide.c
#openpts_SOURCES += aide.c
#uml2dot_SOURCES += aide.c # ctx.c nonce.c
#rm2dot_SOURCES += aide.c

libopenpts_la_SOURCES +=  aide.c

iml2aide_CFLAGS = $(AM_CFLAGS)
iml2aide_LDFLAGS = $(AM_LDFLAGS)
iml2aide_SOURCES = iml2aide.c


# verifier.c ifm.c iml.c ir.c base64.c tpm.c ctx.c \
#conf.c uml.c fsm.c rm.c log.c action.c prop.c policy.c nonce.c tss.c aide.c \
#misc.c snapshot.c reason.c uuid.c ssh.c

#if HAVE_LIBUUID
#iml2aide_SOURCES += uuid_libuuid.c
#else
#iml2aide_SOURCES += uuid_libc.c
#endif
endif

if OPENPTS_BUILD_TBOOT
AM_CPPFLAGS += -DCONFIG_TBOOT
bin_PROGRAMS += tboot2iml
tboot2iml_CFLAGS = $(AM_CFLAGS)
tboot2iml_LDFLAGS = $(AM_LDFLAGS)
tboot2iml_SOURCES = tboot2iml.c
#log.c misc.c
endif



if OPENPTS_BUILD_SQLITE
AM_CPPFLAGS += -DCONFIG_SQLITE
#LDADD += -lsqlite3
AM_LDFLAGS += $(SQLITE_LIBS)
endif

if OPENPTS_BUILD_PQ
AM_CPPFLAGS += -DCONFIG_PQ
AM_LDFLAGS += $(PQ_LIBS)
#LDADD += -lpq
endif

LDADD = $(LIBOBJS)

#IBMSTART
if OPENPTS_BUILD_AUTO_RM_UPDATE
AM_CPPFLAGS += -DCONFIG_AUTO_RM_UPDATE
#ptscd_SOURCES += aru.c
#ptsc_SOURCES += aru.c
#openpts_SOURCES += aru.c
#uml2dot_SOURCES += aru.c ifm.c
#rm2dot_SOURCES += aru.c ifm.c

libopenpts_la_SOURCES +=  aru.c

#if OPENPTS_BUILD_AIDE
#iml2aide_SOURCES += aru.c
#endif
endif
#IBMEND

clean-local:
	@rm -rf *~
	@rm -rf *.gcda
	@rm -rf *.gcno
	@rm -rf *.stat

