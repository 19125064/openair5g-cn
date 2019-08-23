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
# @brief This file is dedicated to Variables set and only variables set. No rules, no targets
#
# @file
#

CPPFLAGS = 
CFLAGS   = $(CPPFLAGS) -Wall -g 
CXXFLAGS = $(CPPFLAGS) -Wall -g -std=c++11

LINK         := g++ -g 
AR           := ar
CODEGEN_CLI  := openapi-generator-cli.sh
CPPREST_ROOT := /usr/



OBJ_DIR := ./obj
# SRC_DIR := ./src
# INC_DIR := ./inc
DEP_DIR := .dep


OBJ = $(SRC:%.cpp=$(OBJ_DIR)/%.o)

DEPFILES = $(SRC:%.cpp=$(DEP_DIR)/%.cpp.d)

DEPTREE = $(addsuffix __file_exist__,$(dir $(DEPFILES)))

