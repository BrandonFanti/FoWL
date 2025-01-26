from .rule_parser import rule_parser
from .translations import rule_token_to_db_lookup, rule_token_to_scapy_translation_layer

from datetime import datetime
ts = datetime.now
from lazy_logger.my_logger import Logger_Base

from scapy.all import *
class WarnConfigParserError(Exception):
    def __init__(self, *args, **kwargs):
        self.name = kwargs.pop('name', None)
        self.rule = kwargs.pop('rule', None)
        self.root_exception = kwargs.pop('exc', None)

class rule:
    name = "FOWL_WALL_RULE"
    log_file=f"log/{name}-Sess-{ts()}.log"
    logger=Logger_Base(name=name, file_path=log_file, log_level=20) #level 20 is info

    def __init__(self, rule_str, name=None, description=None, rule_embed_depth=0, action=None):
        try:
            # self.logger.enable_debug()
            self.name = name
            self.description = description
            self.action = action
            self._raw = rule_str
            self.rule_embed_depth=rule_embed_depth
            self.root_rule = False
            self.origin_rule = self._raw if rule_embed_depth==0 else False
            suffix_rule_parenthesis = False

            self.separators = rule_parser.supported_conditional_separators
            self.comparators = rule_parser.supported_conditional_comparators

            self.database_conditions = []
            self.packet_conditions = []
            self.translated_rules = []

            if not "(" in self._raw and ")" in self._raw:
                self._raw = self._raw[:-1]
                suffix_rule_parenthesis = True

            self.rules_by_separators = rule_parser.alienate_separators(
                self._raw
            )
            self.rules_by_comparators = None

            self.logger.debug(f"Parsing: {self._raw}")
            self.logger.debug(f"  rules seperated: {self.rules_by_separators}")

            #Remove any token in 
            #  - `separators` (also used for comparator filter),
            #  - empty elements,
            #  - or parsed type `rule`
            filter_subrules = lambda rules, seps: [r for r in rules if not r in seps and not r == '' ]
            self.filter_subrules = filter_subrules

            is_non_str_iterable = \
                lambda x: any([
                    hasattr(r, '__iter__') and not isinstance(r, str)
                    for r in x
                ])

            if hasattr(self.rules_by_separators, '__iter__'):
                self.subrules = filter_subrules(self.rules_by_separators, self.separators)
            else:
                self.subrules = self.rules_by_separators

            has_rules_token = lambda rtokens,source_tokens: any([token in source_tokens for token in rtokens])
            has_db_rules_token = lambda st: has_rules_token(rule_token_to_db_lookup.interpreable_root_tokens, st)
            has_scapy_rules_token = lambda st: has_rules_token(rule_token_to_scapy_translation_layer.interpreable_root_tokens, st)

            if hasattr(self.subrules, '__iter__') and not isinstance(self.subrules, str):
                for r in self.subrules:
                    if self._contains_nested_subrules(r):
                        self.logger.debug(f"Nesting subrule: {r}" )
                        rule(r)


            self.logger.debug(f"Testing split subrules: {self.subrules}, {self._contains_nested_subrules(self.subrules)}")

            self.subrules = self.split_all_separators(self.subrules)

            self.logger.debug(f"New subrules: {self.subrules}")

            # if not isinstance(self.rules_by_separators, list): self.rules_by_separators = [self.rules_by_separators]

            if any([comparator in srule for srule in self.rules_by_separators if srule for comparator in self.comparators]):
                self.logger.debug(f"Alienating by comparator token")
                self.rules_by_comparators = [
                    rule_parser.alienate_comparators(rule)
                    for rule in self.rules_by_separators
                ]

            self.logger.debug(f"New comparator splits: {self.rules_by_comparators}")


            if not self.rules_by_comparators:
                if not self.root_rule and self.rules_by_separators:
                    if not any([comparator in srule for srule in self.rules_by_separators if srule for comparator in self.comparators]):
                        self.logger.debug("Should be parsed ...")
                else:
                    self.logger.debug(f"Not parsing booleans because... ")
                    self.logger.debug(f" rule is root? {self.root_rule}")
                    self.logger.debug(f"No seperators? {self.rules_by_separators}")
            else:
                self.logger.debug(f"Not parsing booleans because... ")
                self.logger.debug(f" found comparators: {self.rules_by_comparators}")

            self.root_rule = False

            if self.rules_by_comparators:
                self.root_rule = True if not any([isinstance(e, list) for e in self.rules_by_comparators]) else False

            # self.root_subrules = []
            # if not self.root_rule and self.rules_by_comparators:
            #     for rrule in self.rules_by_comparators:
            #         if isinstance(rrule, list):
            #             #print(r)
            #             rr = rule(r)
            #             if not rr._contains_nested_subrules() and not rr.contains_nested_subrules:
            #                 #print(f"Identified a root rule: {r}")
            #                 self.root_subrules.append(rr)

            self.translated_rules = []

            seperator_index = 1 #Don't start your rules with "and", "or", "&&", or "||"....

            if self.rules_by_comparators:
                for comparator_rule in self.rules_by_comparators:
                    if isinstance(comparator_rule, list):
                        for token in rule_token_to_scapy_translation_layer.interpreable_root_tokens:
                            for rule_token in comparator_rule:
                                if token in rule_token and not any([seperator in ''.join(comparator_rule) for seperator in self.separators]):
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

                        self.logger.debug(f"Checking if scapy rule: {comparator_rule}")
                        if has_rules_token(root_tokens, rule_token_to_scapy_translation_layer.interpreable_root_tokens):
                            self.logger.debug(f"scapy rule confirmed: {comparator_rule}")
                            rule_translation = rule_token_to_scapy_translation_layer.translate_tokenized_condition([comparator_rule])
                            self.translated_rules.append(
                                rule_translation
                            )
                            self.packet_conditions.append(rule_translation)
                            self.logger.debug(f"scapy rule added: {rule_translation}")
                            if seperator_index < len(self.rules_by_separators)-1:
                                self.translated_rules.append(self.rules_by_separators[seperator_index])
                                seperator_index+=1

            if self.rules_by_separators and not self.rules_by_comparators:
                subrules = self.filter_subrules(self.rules_by_separators, self.separators)
                if hasattr(subrules, '__iter__') and not isinstance(subrules, str):
                    for i,subrule in enumerate(subrules):
                        self.logger.debug(f"    Iterating subrule {i}")
                        if rule_parser.has_any_seperable(subrule):
                            self.logger.debug(f"Replacing subrule {subrule}")
                            r = rule(subrule, rule_embed_depth=rule_embed_depth+1)
                            subrules[i] = r
                        else:
                            self.logger.debug(f"Checking if db_lookup rule: {subrule} ({has_db_rules_token(subrule)})")
                            if has_db_rules_token(subrule):  #any([rule in rule_token_to_db_lookup.interpreable_root_tokens for rule in rules]):
                                self.logger.debug(f"db rule confirmed: {subrule}")
                                rule_translation = rule_token_to_db_lookup.translate(subrule)
                                self.translated_rules.append(
                                    rule_translation
                                )
                                self.database_conditions.append(rule_translation)
                                if seperator_index < len(self.rules_by_separators)-1 and isinstance(self.rules_by_separators, list):
                                    self.translated_rules.append(self.rules_by_separators[seperator_index])
                                    seperator_index+=1
                                continue

                            self.logger.debug(f"Checking if scapy rule: {subrule}")
                            if has_scapy_rules_token(subrule):
                                self.logger.debug(f"scapy rule confirmed: {subrule}")
                                rule_translation = rule_token_to_scapy_translation_layer.translate_boolean_statement(subrule)
                                self.logger.debug(f"scapy rule translated: {rule_translation}")
                                self.translated_rules.append(
                                    rule_translation
                                )
                                self.packet_conditions.append(rule_translation)
                                # self.logger.debug(f"scapy rule added: {rule_translation}")
                                if seperator_index < len(self.rules_by_separators)-1 and isinstance(self.rules_by_separators, list):
                                    self.translated_rules.append(self.rules_by_separators[seperator_index])
                                    seperator_index+=1
                        # if len(self.translated_rules)==2:

                else:
                    self.logger.debug("Checking ~~~~~~~~non-iterable rule~~~~~~~~~~~~")

                    self.logger.debug(f"Checking if db_lookup rule: {subrule}")
                    if has_db_rules_token(subrule):  #any([rule in rule_token_to_db_lookup.interpreable_root_tokens for rule in rules]):
                        self.logger.debug(f"db rule confirmed: {subrule}")
                        rule_translation = rule_token_to_db_lookup.translate(subrule)
                        self.translated_rules.append(
                            rule_translation
                        )
                        self.database_conditions.append(rule_translation)
                        if seperator_index < len(self.rules_by_separators)-1 and isinstance(self.rules_by_separators, list):
                            self.translated_rules.append(self.rules_by_separators[seperator_index])
                            seperator_index+=1

                    self.logger.debug(f"Checking if scapy rule: {subrule}")
                    if has_scapy_rules_token(subrule):
                        self.logger.debug(f"scapy rule confirmed: {subrule}")
                        rule_translation = rule_token_to_scapy_translation_layer.translate_boolean_statement(subrule)
                        self.logger.debug(f"scapy rule translated: {rule_translation}")
                        self.translated_rules.append(
                            rule_translation
                        )
                        self.packet_conditions.append(rule_translation)
                        # self.logger.debug(f"scapy rule added: {rule_translation}")
                        if seperator_index < len(self.rules_by_separators)-1 and isinstance(self.rules_by_separators, list):
                            self.translated_rules.append(self.rules_by_separators[seperator_index])
                            seperator_index+=1

                self.subrules = subrules
                self.logger.debug(f"Parsed subrules of CHONK: {subrules}")

            #     if not isinstance(drrule, list): drrule = [drrule]

            #     for rrule in drrule:
            #         root_tokens = rrule.split('.')

            #         self.logger.debug(f"Checking if db_lookup rule: {rrule}")
            #         if has_rules_token(root_tokens, rule_token_to_db_lookup.interpreable_root_tokens):  #any([rule in rule_token_to_db_lookup.interpreable_root_tokens for rule in rules]):
            #             rule_translation = rule_token_to_db_lookup.translate(rrule)
            #             self.translated_rules.append(
            #                 rule_translation
            #             )
            #             self.database_conditions.append(rule_translation)
            #             if seperator_index < len(self.rules_by_separators)-1 and isinstance(self.rules_by_separators, list):
            #                 self.translated_rules.append(self.rules_by_separators[seperator_index])
            #                 seperator_index+=1
            #             continue

            #         self.logger.debug(f"Checking if scapy rule: {rrule}")
            #         if has_rules_token(root_tokens, rule_token_to_scapy_translation_layer.interpreable_root_tokens):
            #             self.logger.debug(f"scapy rule confirmed: {rrule}")
            #             rule_translation = rule_token_to_scapy_translation_layer.translate_boolean_statement(rrule)
            #             self.logger.debug(f"scapy rule translated: {rule_translation}")
            #             self.translated_rules.append(
            #                 rule_translation
            #             )
            #             self.packet_conditions.append(rule_translation)
            #             # self.logger.debug(f"scapy rule added: {rule_translation}")
            #             if seperator_index < len(self.rules_by_separators)-1 and isinstance(self.rules_by_separators, list):
            #                 self.translated_rules.append(self.rules_by_separators[seperator_index])
            #                 seperator_index+=1

            for subrule in self.subrules:
                def get_subrule_translations(subrule):
                    ret = []
                    for subrule_translated in subrule.translated_rules:
                        if subrule_translated == "": subrule_translated = "("
                        self.logger.debug(f"Added {subrule_translated}")
                        ret.append(subrule_translated)
                    return ret
                # if hasattr(self.subrules, '__iter__'):
                #     for r in self.subrules:
                #         if isinstance(r, rule):
                #             self.translated_rules.append('('+''get_subrule_translations(r))
                if isinstance(subrule, rule):
                    self.translated_rules.append(get_subrule_translations(subrule))

            if suffix_rule_parenthesis:
                self.translated_rules.append(")")
                if not '(' in (self.translated_rules[0], self.translated_rules[0][0]):
                    self.translated_rules.insert(0, '(')


            for i,translated_rule in enumerate(self.translated_rules):
                self.logger.debug(f"Should merge '{translated_rule}' ? {is_non_str_iterable(translated_rule)}")
                if not is_non_str_iterable(translated_rule):
                    self.translated_rules[i] = ''.join(translated_rule)

            self.logger.debug(self.translated_rules)

            self.logger.debug(self)

            if self.origin_rule:
                self._translated_rule = ''.join(self.translated_rules)
                self.logger.debug(f"Set translated rule (origin) {self._translated_rule}")
                self.logger.debug(self)
                self.eval_rule = eval(f"lambda pkt, database_cli, **kw: {self._translated_rule}")

        except Exception as e:
            raise WarnConfigParserError(name=name, rule=rule_str, exc=e)

    def call(self, *args, **kwargs):
        self.action(*args, **kwargs)

    def check_conditions(self, engine_pkt_tuple, database_cli=None):
        ts, sock, pkt = engine_pkt_tuple
        return self.eval_rule(pkt, database_cli)

    def split_all_separators(self, subrules):
        while self._contains_nested_subrules(subrules):
            self.logger.debug(f"Splitting_all_separators() in {subrule}")
            rules_with_subrules = self.filter_subrules(subrules, self.separators)
            print(f"Parsing out subrules in {rules_with_subrules}")
            for i,sub_subrule in enumerate(rules_with_subrules):
                if any([seperator in sub_subrule for seperator in self.separators]):
                    print(f"Embedding rule instance for {subrule}")
                    subrules[i] = rule(sub_subrule, rule_embed_depth=self.rule_embed_depth+1)
                    subrules[i] = self.split_all_separators(subrules[i].seperators)
            print(f"Checking if rules has subrules: {self._contains_nested_subrules()}")
        return subrules


    def contains_nested_subrules(self):
        return any([isinstance(subrule,rule) for subrule in self.subrules])

    @staticmethod
    def _contains_nested_subrules(rules):
        if hasattr(rules, '__iter_-'):
            for r in rules:
                for separator in rule_parser.supported_conditional_separators:
                    if isinstance(r, str)\
                        and separator in r \
                        and not separator == r:
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