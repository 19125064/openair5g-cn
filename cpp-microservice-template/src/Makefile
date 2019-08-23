##
##############################################################################
# @b Project : New-Edge
#
# @b Sub-project : MicroServices
#
##############################################################################
#
#                       Copyright (C) B<>COM
#                       B<>COM - PROPRIETARY
#
#       Disclosure to third parties or reproduction in any form what-
#       soever, without prior written consent, is strictly forbidden
#
##############################################################################
#
# <b>Creation date :</b> 2018.05.25
# <b>By :</b>            Cyrille Bénard
#
#
# @brief Entry point to build and install all the project targets
#        No variables nor rules should be declared in this file, see variables.mk and rules.mk
#
# @file
#

all:
	$(MAKE) $(MFLAGS) -C ./client
	$(MAKE) $(MFLAGS) -C ./server
	
install:
	$(MAKE) $(MFLAGS) -C ./server $@

	
uninstall:
	$(MAKE) $(MFLAGS) -C ./server $@

help:
	$(MAKE) $(MFLAGS) -C ./server $@

clean:
	$(MAKE) $(MFLAGS) -C ./client $@
	$(MAKE) $(MFLAGS) -C ./server $@
