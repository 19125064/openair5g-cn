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
# @brief Entry point to build AND install the generated application
#        Please, have a look below for the manual/usage
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
#    all | <empty>   Build the micro service
#
#    clean           Clean up all the generated files
#
#    help            Print the manual
#
#    install         Install the application 
#
#    uninstall       Fully uninstall the application from the system
#
#    dump            This is for developer usage. Dump a variable content using VAR to
#                    define the variable name, VAR=<variable name>
#
# Note:
#   To install/uninstall you MUST have permissions 
#
# Examples:
#   make
#   make -n
#   make help
#   make clean
#   make install
#   make dump VAR=TARGET
#
# MANUAL END




include ../variables.mk

########################################################
# User may redefines some default values, see below
########################################################
#


# Default Micro Service name
# This is the name retrieve from the directory name where the OpenApi file is
# stored (the directory must fit the syntax : "api-<ms name>"
MS_NAME := $(patsubst ../../api-%,%, $(wildcard ../../api-*))

# Project name is the server name (binary file)
PROJECT_NAME := server-$(MS_NAME)

# Default OpenApi input file
CODEGEN_INPUT := $(wildcard ../../api-*/openapi.yaml)

# Default code generator configuration file
# If no configuration file is created by the user, the makefile process
# will automatically create one
CODEGEN_CONF := ./config.json

# Add the generated folders to the include path research
CPPFLAGS += -I./api -I./model -I./impl

# Add automatically all the client include path
CPPFLAGS += $(addprefix -I, $(wildcard ../client/*/gen-cpp/api))

# Add automatically all OpenApi Client libs declared inside this Micro Service
LIBS += $(wildcard ../client/*/gen-cpp/lib/*.a)

# External library installed on the station (not project libs)
EXT_LIB = -lpistache -lpthread

TARGET  := $(PROJECT_NAME)

#
##########################################################
# User is not supposed to modify something below this line
##########################################################

$(filter-out $(mains),$(objects))

SRC =	\
	$(wildcard api/*.cpp)    \
	$(wildcard model/*.cpp)  \
    $(wildcard impl/*.cpp)


CODEGEN_OUTPUT := ./CMakeLists.txt

all: $(TARGET)

#
# Link the TARGET with all its dependencies, starting with the second object in the list
$(TARGET): $(CODEGEN_OUTPUT) $(OBJ) $(LIBS)
	$(LINK) $(LDFLAGS) -o $@ $(wordlist 2, $(words $^), $^) $(EXT_LIB)

$(CODEGEN_OUTPUT): $(CODEGEN_INPUT) $(CODEGEN_CONF)
	$(CODEGEN_CLI) generate -i $(CODEGEN_INPUT) -g cpp-pistache-server -c $(CODEGEN_CONF) -o .
	@echo
	@echo "**************************************************************************"
	@echo "** This is not an error"
	@echo "** You may have to update the new API produced in impl/DefaultApiImpl.*" 
	@echo "** inside your code (if any). Files impl/DefaultApiImpl.* are not compiled"
	@echo "** nor linked"
	@echo "**************************************************************************"
	@echo "** If this is the first time you launch make, you need to copy/paste"
	@echo "** impl/DefaultApiImpl.* into others names in the same folder"
	@echo "** Like impl/<MicroServiceName>ApiImpl.* for example"
	@echo "**************************************************************************"
	@echo "** Do it (if any) and relaunch the build"
	@echo "**************************************************************************"
	@echo
	@false

# In case the user does not want to specialize and define manually the swagger
# configuration, this target do it, espacially the namespaces
$(CODEGEN_CONF):
	@echo '{' > $@
	@echo '    "modelPackage"   : "com.bcom.nf.microservice.server.$(MS_NAME).model",' >> $@
	@echo '    "apiPackage"     : "com.bcom.nf.microservice.server.$(MS_NAME).api"'    >> $@
	@echo '}' >> $@


help:
	@cat Makefile| grep -n MANUAL | cut -d: -f1 | xargs | awk '{ print "sed -n "$$1+1","$$2-1"p Makefile"}' | $(SHELL)


install: server_install
	@echo Install completed successfully

uninstall: server_uninstall
	@echo Uninstall completed successfully


server_install:
	@echo TODO
	@false
	@echo "Install completed successfully"

server_uninstall:  
	@echo TODO
	@false
	@echo "Uninstall completed successfully"


#
# Clean all produced files, avoiding the json.hpp deletion
#
clean:
	-rm -rf $(TARGET) $(CODEGEN_OUTPUT) $(OBJ_DIR)/* $(DEP_DIR)/* api/*
	-find model -type f -not -name json.hpp -exec rm {} \;

#
# Do not read and update all dependencies in case the target is clean.
# This would be stupid to rebuild them before erase them :^)
#
ifneq ($(MAKECMDGOALS),clean)
-include $(DEPFILES)
endif

include ../debug.mk

include ../rules.mk

-include $(DEPTREE)
