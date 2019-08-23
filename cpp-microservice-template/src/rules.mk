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
# @brief All general rules are stored here and only rules. No dedicated/specific target is allowed
#
# @file
#

$(DEP_DIR)/%.c.d: $(SRC_DIR)/%.c
	@echo Updating dependencies of $<
	@$(SHELL) -fec '$(CC) -MM $(CFLAGS) $< \
                      | sed '\''s;$*\.o[ :]*;$(OBJ_DIR)/$*\.o $@ : ;g'\'' > $@; \
                     [ -s $@ ] || ( $(RM) $@ ; exit 1 )'

$(DEP_DIR)/api/%.cpp.d: api/%.cpp
	@echo Updating dependencies of $<
	@$(SHELL) -fec '$(CC) -MM $(CXXFLAGS) $< \
                      | sed '\''s;$*\.o[ :]*;$(OBJ_DIR)/api/$*\.o $@ : ;g'\'' > $@; \
                     [ -s $@ ] || ( $(RM) $@ ; exit 1 )'

$(DEP_DIR)/model/%.cpp.d: model/%.cpp
	@echo Updating dependencies of $<
	@$(SHELL) -fec '$(CC) -MM $(CXXFLAGS) $< \
                      | sed '\''s;$*\.o[ :]*;$(OBJ_DIR)/model/$*\.o $@ : ;g'\'' > $@; \
                     [ -s $@ ] || ( $(RM) $@ ; exit 1 )'

$(DEP_DIR)/impl/%.cpp.d: impl/%.cpp
	@echo Updating dependencies of $<
	@$(SHELL) -fec '$(CC) -MM $(CXXFLAGS) $< \
                      | sed '\''s;$*\.o[ :]*;$(OBJ_DIR)/impl/$*\.o $@ : ;g'\'' > $@; \
                     [ -s $@ ] || ( $(RM) $@ ; exit 1 )'


%/__file_exist__:
	@mkdir -p $* && touch $@

$(OBJ_DIR)/api/%.o: api/%.cpp
	@mkdir -p $(dir $@)
	@echo Building the object file $@ from $<
	$(CMD_PREFIX)$(CXX) -c $(CXXFLAGS) -o $@ $<
	@echo

$(OBJ_DIR)/model/%.o: model/%.cpp
	@mkdir -p $(dir $@)
	@echo Building the object file $@ from $<
	$(CMD_PREFIX)$(CXX) -c $(CXXFLAGS) -o $@ $<
	@echo

$(OBJ_DIR)/impl/%.o: impl/%.cpp
	@mkdir -p $(dir $@)
	@echo Building the object file $@ from $<
	$(CMD_PREFIX)$(CXX) -c $(CXXFLAGS) -o $@ $<
	@echo

