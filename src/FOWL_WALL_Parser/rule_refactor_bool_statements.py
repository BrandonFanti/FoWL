from .rule_parser import rule_parser
from .translations import rule_token_to_db_lookup, rule_token_to_scapy_translation_layer

from datetime import datetime
ts=datetime.now
from lazy_logger.my_logger import Logger_Base

class WarnConfigParserError(Exception):
    def __init__(self, *args, **kwargs):
        self.name = kwargs.pop('name', None)
        self.rule = kwargs.pop('rule', None)
        self.root_exception = kwargs.pop('exc', None)

class rule:
    pass
class rule:
    name = "FOWL_WALL_RULE"
    log_file=f"log/{name}-Sess-{ts()}.log"
    logger=Logger_Base(name=name, file_path=log_file, log_level=20) #level 20 is info


    def __init__(self, rule_str, name=None, description=None, rule_embed_depth=0, action=None):
        try:
            if rule_str == "": 
                self.logger.debug("WTF is an empty rule supposed to do?!")
                return
            self.logger.enable_debug()
            self.name = name
            self.description = description
            self.action = action
            self._raw = rule_str
            self.rule_embed_depth=rule_embed_depth
            self.root_rule = False
            suffix_rule_parenthesis = False
            self.subrules = []
            
            separators = rule_parser.supported_conditional_separators
            comparators = rule_parser.supported_conditional_comparators

            self.database_conditions = []
            self.packet_conditions = []


            if not "(" in self._raw and ")" in self._raw:
                self._raw = self._raw[:-1]
                suffix_rule_parenthesis = True

            self.rules_by_separators = rule_parser.alienate_separators(
                self._raw
            )
            self.rules_by_comparators = None

            filter_subrules = lambda x: [rule for rule in self.rules_by_separators if not rule in separators and not rule == '' and len(rule)>1]

            if not any([' ' in rule for rule in self.rules_by_separators]):
                subrules = filter_subrules(self.rules_by_separators)
            else: 
                subrules = filter_subrules(self.rules_by_separators)

            self.filter_subrules = filter_subrules
            has_rules_token = lambda rtokens,source_tokens: any([token in source_tokens for token in rtokens])
            has_db_rules_token = lambda rt: has_rules_token(rt, rule_token_to_db_lookup.interpreable_root_tokens)
            has_scapy_rules_token = lambda rt: has_rules_token(rt, rule_token_to_scapy_translation_layer.interpreable_root_tokens)

            if subrules:
                self.subrules = subrules
                self.logger.debug(f"Rule has subrules {self.subrules}")
                while self._contains_nested_subrules():
                    rules_with_subrules = filter_subrules(subrules)
                    #print(f"Parsing out subrules in {rules_with_subrules}")
                    for i,subrule in enumerate(rules_with_subrules):
                        self.logger.debug(f"Parsing subrule {subrule}")
                        if any([seperator in subrule for seperator in separators]):
                            #print(f"Embedding rule instance for {subrule}")
                            if subrule == '': continue
                            subrules[i] = rule(subrule, rule_embed_depth=rule_embed_depth+2)
                    self.subrules = subrules
                    #print(f"Checking if rules has subrules: {self._contains_nested_subrules()}")


                if any([comparator in srule for srule in self.rules_by_separators if srule for comparator in comparators]):
                    self.rules_by_comparators = [
                        rule_parser.alienate_comparators(rule)
                        for rule in self.rules_by_separators
                    ]


            # if isinstance(self.rules_by_separators,list):
            #     self.logger.debug("Iterating seperators")
            #     for e in self.rules_by_separators:
            #         self.logger.debug(f"isinstance({e}, list): {isinstance(e, list)}")
            # if isinstance(self.rules_by_comparators,list):
            #     self.logger.debug("Iterating comparators")
            #     for e in self.rules_by_comparators:
            #         self.logger.debug(f"isinstance({e}, list): {isinstance(e, list)}")
                
                #True if not any([isinstance(e, list) for e in [*self.rules_by_comparators, *self.rules_by_separators]]) else False

            if not isinstance(self.rules_by_separators, list) and not self.rules_by_comparators:
                self.root_rule = True



            self.root_subrules = []

            if not self.root_rule and self.rules_by_separators:
                for rrule in self.rules_by_separators:
                    if not isinstance(rrule, list):
                        rr = rule(rrule)
                        if not rr._contains_nested_subrules():
                            self.root_subrules.append(rr)



            if not self.root_rule and self.rules_by_comparators:
                for rrule in self.rules_by_comparators:
                    if isinstance(rrule, list):
                        r=''.join(rrule)
                        #print(r)
                        rr = rule(r)
                        if not rr._contains_nested_subrules() and not rr.contains_nested_subrules:
                            #print(f"Identified a root rule: {r}")
                            self.root_subrules.append(rr)

            self.translated_rules = []

            seperator_index = 1 #Don't start your rules with "and", "or", "&&", or "||"....

            #Parse and nest comparator rules
            if self.rules_by_comparators:
                for comparator_rule in self.rules_by_comparators:
                    if isinstance(comparator_rule, list):
                        for token in rule_token_to_scapy_translation_layer.interpreable_root_tokens:
                            for rule_token in comparator_rule:
                                if token in rule_token and not any([seperator in ''.join(comparator_rule) for seperator in separators]):
                                    self.logger.debug(f"Translating rule token {rule_token} from {comparator_rule}")
                                    translated_rule = rule_token_to_scapy_translation_layer.translate_tokenized_condition(comparator_rule)
                                    self.logger.debug(f"Adding {translated_rule}")
                                    self.translated_rules.append(
                                        translated_rule
                                    )
                                    self.packet_conditions.append(translated_rule)
                                    if seperator_index < len(self.rules_by_separators)-1:
                                        self.translated_rules.append(self.rules_by_separators[seperator_index])
                                        seperator_index+=1

                    if not rule_parser.has_any_seperable(comparator_rule):
                        root_tokens = comparator_rule.split('.')

                        self.logger.debug(f"Checking if db_lookup rule: {comparator_rule}")
                        if has_rules_token(root_tokens, rule_token_to_db_lookup.interpreable_root_tokens):  #any([rule in rule_token_to_db_lookup.interpreable_root_tokens for rule in rules]):
                            rule_translation = rule_token_to_db_lookup.translate(comparator_rule)
                            self.translated_rules.append(
                                rule_translation
                            )
                            self.database_conditions.append(rule_translation)
                            if seperator_index < len(self.rules_by_separators)-1:
                                self.translated_rules.append(self.rules_by_separators[seperator_index])
                                seperator_index+=1
                            continue

                        self.logger.debug(f"Checking if scapy rule: {comparator_rule} ({root_tokens})")
                        if has_rules_token(root_tokens, rule_token_to_scapy_translation_layer.interpreable_root_tokens):
                            self.logger.debug(f"scapy rule found: {comparator_rule} ({root_tokens})")
                            rule_translation = rule_token_to_scapy_translation_layer.translate_tokenized_condition([comparator_rule])
                            self.logger.debug(f"scapy rule translated: {comparator_rule} -> ({rule_translation})")
                            self.translated_rules.append(
                                rule_translation
                            )
                            self.packet_conditions.append(rule_translation)
                            if seperator_index < len(self.rules_by_separators)-1:
                                self.translated_rules.append(self.rules_by_separators[seperator_index])
                                seperator_index+=1

            #If there aren't any split comparator statements or nested rules,
            #  then the rule is a boolean statement, like 
            # `tcp.syn`, `host.banned`, or `host.banned and tcp.syn`
            if not self.rules_by_comparators and self.root_rule and self.rules_by_separators:
                self.logger.debug(f"(compound?) boolean statement rule detected: {self.rules_by_separators}")
                seperator_index=0
                root_tokens = self.rules_by_separators.split('.')

                if has_rules_token(root_tokens, rule_token_to_db_lookup.interpreable_root_tokens):
                    self.logger.debug(f"database rule found: {self.rules_by_separators} ({root_tokens})")
                    rule_translation = rule_token_to_scapy_translation_layer.translate_boolean_statement(self.rules_by_separators)
                    self.logger.debug(f"database rule translated: {self.rules_by_separators} -> ({rule_translation})")
                    self.translated_rules.append(
                        rule_translation
                    )
                    self.database_conditions.append(rule_translation)

                if has_rules_token(root_tokens, rule_token_to_scapy_translation_layer.interpreable_root_tokens):
                    self.logger.debug(f"scapy rule found: {self.rules_by_separators} ({root_tokens})")
                    rule_translation = rule_token_to_scapy_translation_layer.translate_boolean_statement(self.rules_by_separators)
                    self.logger.debug(f"scapy rule translated: {self.rules_by_separators} -> ({rule_translation})")
                    self.translated_rules.append(
                        rule_translation
                    )
            else:
                for subrule in self.subrules:
                    if isinstance(subrule, rule):
                        for subrule_translated in subrule.translated_rules:
                            if subrule_translated == "": subrule_translated = "("
                            self.logger.debug(f"Added {subrule_translated}")
                            self.translated_rules.append(subrule_translated)

            if suffix_rule_parenthesis:
                self.translated_rules.append(")")

            self.logger.debug(f"~~~~~New Translated Rules: {self.translated_rules}")

            self._translated_rule = ''.join(self.translated_rules)
            self.logger.debug(f"~~~~~New Translated Rule: {self._translated_rule}")

            self.logger.debug(self)

        except Exception as e:
            raise WarnConfigParserError(name=name, rule=rule_str, exc=e)

    def call(self, *args, **kwargs):
        self.action(*args, **kwargs)

    def check_conditions(self, engine_pkt_tuple, database_cli=None):
        ts, sock, pkt = engine_pkt_tuple
        condition_result = eval(self._translated_rule)
        return condition_result





    def contains_nested_subrules(self):
        return any([isinstance(subrule,rule) for subrule in self.subrules])

    def _contains_nested_subrules(self):
        for rule in self.subrules:
            for seperator in rule_parser.supported_conditional_separators:
                if isinstance(rule, str)\
                    and seperator in rule \
                    and not seperator == rule:
                    return True
        return False

    def translate(self):
        return 

    def __str__(self):

        translated_rules_str = f"{'    '*(self.rule_embed_depth+3)}" + \
                f",\n{'    '*(self.rule_embed_depth+3)}".join(self.translated_rules)
                #     str(rule.translated) 
                # for rule in self.translated_rules 
                #     if not isinstance(rule, str))


        if self.contains_nested_subrules():
            subrule_str =  f"{'    '*(self.rule_embed_depth+1)}" + \
                f",\n{'    '*(self.rule_embed_depth+1)}".join(str(rule) for rule in self.subrules if not isinstance(rule, str))

            return  f"""{'    '*self.rule_embed_depth}Raw Rule: {self._raw}\n""" + \
                    f"""{'    '*(self.rule_embed_depth+1)}    to_run: {str(self.action)}\n"""+\
                    f"""{'    '*(self.rule_embed_depth+1)}    rule_is_root: {self.root_rule}\n"""+\
                    f"""{'    '*(self.rule_embed_depth+1)}    separators  : {self.rules_by_separators}\n"""+\
                    f"""{'    '*(self.rule_embed_depth+1)}    comparators : {self.rules_by_comparators}\n"""+\
                    f"""{'    '*(self.rule_embed_depth)}        subrules: [\n"""+\
                        subrule_str + \
                    f"\n    {'    '*self.rule_embed_depth}    ]\n" +\
                    f"""{'    '*(self.rule_embed_depth+1)}rules_translated: [\n"""+\
                        translated_rules_str + \
                    f"\n    {'    '*(self.rule_embed_depth)}]\n" 

        else:
            return  f"""{'    '*self.rule_embed_depth}Raw Rule: {self._raw}\n""" + \
                    f"""{'    '*(self.rule_embed_depth+1)}    to_run: {str(self.action)}\n"""+\
                    f"""{'    '*(self.rule_embed_depth+1)}    rule_is_root: {self.root_rule}\n"""+\
                    f"""{'    '*(self.rule_embed_depth+1)}    separators  : {self.rules_by_separators}\n"""+\
                    f"""{'    '*(self.rule_embed_depth+1)}    comparators : {self.rules_by_comparators}\n"""+\
                    f"""{'    '*(self.rule_embed_depth+2)}rules_translated: [\n"""+\
                        translated_rules_str + \
                    f"\n    {'    '*(self.rule_embed_depth+1)}]\n" 