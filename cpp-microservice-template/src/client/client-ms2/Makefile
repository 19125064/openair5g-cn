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
#
# @brief Entry point to build the current client library
#
#
# @file
#

# MANUAL START
#
# Usage: make [options] [target]
#
# options:
#    Any options defined by make
#
# target:
#
#    all | <empty>   Build the micro service client library defined by the OpenApi file
#                    under api-<ms name>/openapi.yaml
#
#    clean           Clean up all the generated files
#
#    help            Print the manual
#
#    dump            This is for developer usage. Dump a variable content using VAR to
#                    define the variable name, VAR=<variable name>
#
# Specialization:
#                   User may specialize this Makefile to fit to its need but, by default,
#                   it will produce a static library under gen-cpp/lib with its api defined
#                   in gen-cpp/api. Files names will be, by default :
#                       - libclient-<ms name>.a
#                       - client-<ms name>.h
#
#                   To specialize some targets or names, have a look to the section under this manual
#                   inside the Makefile
#
# Examples:
#   make
#   make -n
#   make help
#   make clean
#   make dump VAR=PROJECT_NAME
#
# MANUAL END



include ../../variables.mk

#
########################################################
# User may redefines some default values, see below
########################################################
#

# Default project name is current dir name (relative)
PROJECT_NAME := $(notdir $(shell pwd))

# Default Micro Service name
MS_NAME := $(patsubst client-%,%,$(PROJECT_NAME))

# Default OpenApi input file
CODEGEN_INPUT := $(wildcard ./api-*/openapi.yaml)

# Default code generation configuration file
# If no configuration file is created by the user, the makefile process
# will automatically create one
CODEGEN_CONF := ./config.json

#
##########################################################
# User is not supposed to modify something below this line
##########################################################
#
GEN_CPP                     := gen-cpp
CODEGEN_OUTPUT              := $(GEN_CPP)/CMakeLists.txt
CMAKE_OUTPUT                := $(OBJ_DIR)/Makefile
CODEGEN_MODIFY_PROJECT_NAME := $(CODEGEN_OUTPUT).tmp


TARGET := ./lib/lib$(PROJECT_NAME).a


all: $(TARGET) 

.phony: FORCE

FORCE:


$(TARGET): $(CODEGEN_OUTPUT) $(CODEGEN_MODIFY_PROJECT_NAME) $(CMAKE_OUTPUT) FORCE
	$(MAKE) $(MFLAGS) -C $(OBJ_DIR)



$(CODEGEN_OUTPUT): $(CODEGEN_INPUT) $(CODEGEN_CONF)
	$(CODEGEN_CLI) generate -i $(CODEGEN_INPUT) -g cpp-restsdk -c $(CODEGEN_CONF) -o $(GEN_CPP)

$(CMAKE_OUTPUT): $(CODEGEN_OUTPUT)
	@mkdir -p $(OBJ_DIR)
	cd $(OBJ_DIR) ; cmake -D CPPREST_ROOT=$(CPPREST_ROOT) ../$(GEN_CPP) 

#
# Modify the project name after the code generation. Touch is used to avoid
# the update of the file date and so, avoid to interfer between the input and output files.
# I mean, I don't want to interfere inside the consistence maintained by the make system between
# target and dependencies
$(CODEGEN_MODIFY_PROJECT_NAME): $(CODEGEN_OUTPUT)
	@touch -r $< $@
	@sed 's;project(.*);project($(PROJECT_NAME));g' -i $<
	@touch -r $@ $<


# In case the user does want to specialize and define manually the code generation
# configuration, this target do it, espacially the namespaces
$(CODEGEN_CONF):
	@echo '{' > $@
	@echo '    "modelPackage"   : "com.bcom.nf.microservice.client.$(MS_NAME).model",' >> $@
	@echo '    "apiPackage"     : "com.bcom.nf.microservice.client.$(MS_NAME).api"'    >> $@
	@echo '}' >> $@




help:
	@cat Makefile| grep -n MANUAL | cut -d: -f1 | xargs | awk '{ print "sed -n "$$1+1","$$2-1"p Makefile"}' | $(SHELL)


clean:
	-rm -rf $(OBJ_DIR) $(GEN_CPP)
#	-rm -rf $(TARGET) $(CODEGEN_OUTPUT) $(OBJ_DIR) $(GEN_CPP)


include ../../debug.mk

