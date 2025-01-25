from sys import argv, path
path.append('src')
path.append('.')

import json
from importlib import import_module
import inspect
from traceback import format_exception
import notify

from netfilter_manager import netfilter_manager

import re
from datetime import datetime, timedelta
ts = datetime.now

from lazy_logger.my_logger import Logger_Base
name = "FOWL_WALL_RULE"
log_file=f"log/{name}-Sess-{ts()}.log"
logger=Logger_Base(name=name, file_path=log_file, log_level=20) #level 20 is info

# logger.enable_debug()

from scapy.all import TCP, DHCP, IP, UDP

def import_function_handler(reference:str) -> callable or None:
    """ Get a memory-backed function reference
    
        param: reference from a string like "logging.info" (e.g. `import logging; logging.info()`)
        returns: a pointer to the function instance, or None 
    """
    module, funct = reference.split('.')
    #print(f"Looking for `{funct}()` in module `{module}`")
    this_module = import_module(module)
    if funct in dir(this_module):
        #print(f"Importing `{funct}`")
        funct = this_module.__getattribute__(funct)
        if hasattr(funct,'__call__'):
            del this_module
            return funct
    del this_module
    return 




class WarnConfigParserError(Exception):
    def __init__(self, *args, **kwargs):
        pass


class rule_token_to_db_lookup:
    interpreable_root_tokens = ['host']

    def translate(token):
        if 'banned' in token:
            return f"database_cli.get('{token}')"


class rule_token_to_scapy_translation_layer:
    interpreable_root_tokens = ['device', 'tcp', 'dhcp', 'net']
    STATEMENT_NONE=0
    STATEMENT_BIFURCATES=1
    STATEMENT_CONVERGE=2
    STATEMENT_ARG_0=3
    STATEMENT_ARG_1=4
    direct_translations={

    }

    def __init__(self):
        pass

    @classmethod
    def translate(*args):
        _cls, token = args
        #device is db meta for mac and IP
        #e.g. expansion of:
        # device.mac == 'D3:4D:B3:3F:D3:4D'
        #  would be 
        # pkt.hasLayer(mac) and (pkt.mac.src == 'D3:4D:B3:3F:D3:4D' or pkt.mac.dst == 'D3:4D:B3:3F:D3:4D')
        #print(f"Translator received token: {token}")
        if token in ['True', 'False']: return (token, (_cls.STATEMENT_NONE, None))

        ctx_evaluable = ''

        if 'device' in token:
            subtokens = [st.strip() for st in token.split('.')]
            #print('\t'+str(subtokens))
            if subtokens[-1] == 'mac': 
                subtokens[-1]='Ether'
                ctx_lookup = ('[Ether].src','[Ether].dst')
            elif subtokens[-1] == 'ip': 
                subtokens[-1]='IP'
                ctx_lookup = ('[IP].src','[IP].dst')
            ctx_evaluable=f"pkt.haslayer({subtokens[-1]})"
            return (ctx_evaluable,(_cls.STATEMENT_BIFURCATES, ctx_lookup)) #but also reconverges?

        if 'net.' in token:
            subtokens = [st.strip() for st in token.split('.')]
            logger.debug(f"Processing token: {token}, with subtokens {subtokens}")
            core_rule_part = ''

            ctx_evaluable = f"(pkt.haslayer(TCP) or pkt.haslayer(UDP))"
            ctx_lookup = ('.sport','.dport')

            if subtokens[1] == 'port':
                return (ctx_evaluable,(_cls.STATEMENT_CONVERGE, ctx_lookup)) 
            elif subtokens[1] == 'src':
                return (ctx_evaluable,(_cls.STATEMENT_ARG_0, ctx_lookup)) 
            elif subtokens[1] == 'dst':
                return (ctx_evaluable,(_cls.STATEMENT_ARG_1, ctx_lookup)) 


        if 'tcp' in token:
            ctx_evaluable = f"pkt.haslayer(TCP)"
            subtokens = token.split('.')
            if subtokens[1] in ('syn','ack','rst','fin'):
                ctx_evaluable += f" and pkt[TCP].flags == '{subtokens[1][0].upper()}'"

        if token.upper() in ('DHCP',):#Replace with statics: _cls.direct_translations[token.upper()]
            ctx_evaluable=f"pkt.haslayer({token.upper()})"

        if token != '' and (token[0] == "'" or token[0] == '"'):
            ctx_evaluable=token

        return (ctx_evaluable, (_cls.STATEMENT_NONE, None))

    @classmethod
    def translate_tokenized_condition(*args):
        _cls, condition = args
        new_condition,other  = _cls.translate(condition[0])

        if _cls.STATEMENT_BIFURCATES in other:
            _, ctx_lookup = other
            ctx_lookup, ctx_lookup_alt = ctx_lookup
            new_condition += f" and (pkt{ctx_lookup} {condition[1]} {condition[2]}"
            new_condition += f" or pkt{ctx_lookup_alt} {condition[1]} {condition[2]})"

        if _cls.STATEMENT_CONVERGE in other:
            _, ctx_lookup = other
            ctx_lookup, ctx_lookup_alt = ctx_lookup
            new_condition += f" and (pkt{ctx_lookup} {condition[1]} {condition[2]}"
            new_condition += f" and pkt{ctx_lookup_alt} {condition[1]} {condition[2]})"

        if _cls.STATEMENT_ARG_0 in other:
            _, ctx_lookup = other
            ctx_lookup, _ = ctx_lookup
            new_condition += f" and pkt{ctx_lookup} {condition[1]} {condition[2]}"
        if _cls.STATEMENT_ARG_1 in other:
            _, ctx_lookup = other
            _, ctx_lookup_alt = ctx_lookup
            new_condition += f" and pkt{ctx_lookup_alt} {condition[1]} {condition[2]}"



        #print(f"translate_condition(): returning new condition : {new_condition}")

        return new_condition


class rule_parser:
    supported_conditional_separators = ( "(", " and ", " or ", "&&", "||")
    supported_conditional_comparators = ("==","!=", "<=", ">=", ">", "<")

    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def has_any_seperable(rule):
        return any([
            rule_parser.get_splittable_seperator_token(rule),
            rule_parser.get_splittable_comparator_token(rule)
        ])

    @classmethod 
    def get_splittable_seperator_token(_cls, rule:str):
        for token in _cls.supported_conditional_separators:
            if token in rule:
                return token

    @classmethod 
    def get_splittable_comparator_token(_cls, rule:str):
        #print(f"Looking for comparator in rule: {rule}")
        for token in _cls.supported_conditional_comparators:
            if token in rule:
                return token

    @classmethod
    def alienate_separators(_cls, rule):
        token = _cls.get_splittable_seperator_token(rule)
        if token == "(":
            parenthetical_group_match = re.findall("\(.*\)", rule, flags=re.DOTALL)[0]
            rules_parenthetically_split = rule.split(parenthetical_group_match)
            for i,rp in enumerate(rules_parenthetically_split):
                if rp == '':
                    rules_parenthetically_split[i] = parenthetical_group_match
                    #print(rules_parenthetically_split)
                    if i-1 < 0:
                        #print("Alienating next element")
                        as_ng = _cls.alienate_separators(rules_parenthetically_split[i+1])
                        #print(as_ng[2])
                        as_ng[2] = as_ng[2]+parenthetical_group_match
                        #print(as_ng)
                    else:
                        #print("Alienating previous element")
                        #print(_cls.alienate_separators(rules_parenthetically_split[i-1]))
                        as_ng = _cls.alienate_separators(rules_parenthetically_split[i-1])
                        #print(as_ng[2])
                        as_ng[2] = as_ng[2]+parenthetical_group_match
                        #print(as_ng)

        if token:
            tokenized = rule.split(token)
            return [tokenized[0], token, tokenized[1]]
        else: return rule

    @classmethod
    def alienate_comparators(_cls, rule):
        token = _cls.get_splittable_comparator_token(rule)
        if token:
            tokenized = rule.split(token)
            if len(tokenized) > 1:
                return [tokenized[0], token, tokenized[1]]
            else: return rule
        else: return rule

    @classmethod
    def alienate(_cls, rule, separators):
        change = False
        conditionals_split=[rule]
        if any(condition in rule for condition in separators):
            for condition in separators:
                for splitt in conditionals_split:
                    if condition in splitt and condition != splitt:
                        #print(f"\tSplitting '{splitt}' with '{condition}'")
                        change=True
                        conditionals_split=[token.strip() for token in splitt.split(condition)]
                        conditionals_split.insert(1, condition)
                        break
                break
        else: return rule

        if change: 
            return [_cls.alienate(subtokens, separators) for subtokens in conditionals_split] 
        return conditionals_split[0]

    @classmethod
    def _tokenizer(*args):
        _cls, rules = args

        all_rule_tokens=[]
        if isinstance(rules, str): rules=[rules]
        for i,rule in enumerate(rules):
            rule = _cls.alienate(rule, _cls.supported_conditional_separators)
            #print(f"First pass of separators: {rule}")
            rule = _cls.alienate(rule, _cls.supported_conditional_comparators)
            #print(f"Second pass of conditionals: {rule}")


            # rule_tokens = []
            # if any(condition in conditionals_split for condition in _cls.supported_conditional_comparators):
            #     for condition in _cls.supported_conditional_comparators:
            #         if condition in rule_tokens:
            #             rule_tokens = [token.strip() for token in rule_tokens.split(condition)]
            #             rule_tokens.insert(1, condition)
            #             break
            #         else: continue
            # all_rule_tokens.append(rule_tokens)

        #print(f"All subconditions tokenized: {all_rule_tokens}")
        #TODO: Lexer?

        rts_stl = rule_token_to_scapy_translation_layer
        new_condition = ""
        for condition in all_rule_tokens:
            #print(f"_tokenizer sending condition to ", end='')
            # if not a true condition: translate the token
            if len(condition) <= 1 and isinstance(condition, str): 
                #print(f" {condition} translate().")
                new_condition += rts_stl.translate(condition)[0]
                continue
            #If true condition:
            #print(f" {condition} translate_tokenized_condition().")
            new_condition += rts_stl.translate_tokenized_condition(condition)
        #print(f"_tokenizer returning condition: {new_condition}")
        return new_condition



    @classmethod
    def parse(*args) -> callable:
        #print(args)
        _cls, _rule  = args

        #print(f"Parsing rule: {_rule}")
        #TODO: finish parenthetical groups like "tcp and (host.src == $x or host.dst == $x)"
        # conditional_groups = rule.find_rule

        discrete_unilateral_conditions = [rule.strip() for rule in _rule.split(' or ')]
        discrete_conditions = [rule.strip() for rule in _rule.split(' and ')]

        #print(f"descrete uni cond: {discrete_unilateral_conditions}")
        #print(f"descrete cond: {discrete_conditions}")

        #print("Running tokenizer")

        #print(_cls._tokenizer(_rule))

        rules = []
        # for condition in discrete_conditions:
        #     rules.append(_cls._tokenizer(condition))

        unilateral_rules=[]
        # for condition in discrete_unilateral_conditions:
        #     unilateral_rules.append(_cls._tokenizer(condition))

        #print(f"All tokens for rule `{_rule}`: Translate to...")
        for rule in rules:
            #print(f"\t\t\t   {rule}")
            pass
        for rule in unilateral_rules:
            #print(f"\t(unilateral rules):{rule}")
            pass

        #TODO: Finish translation layer(rule_token_translation_layer), then this
        return lambda x: True

class rule:

    def __init__(self, rule_str, name=None, description=None, rule_embed_depth=0, action=None):
        self.name = name
        self.description = description
        self.action = action
        self._raw = rule_str
        self.rule_embed_depth=rule_embed_depth
        suffix_rule_parenthesis = False

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

        filter_subrules = lambda x: [rule for rule in self.rules_by_separators if not rule in separators ]
        subrules = filter_subrules(self.rules_by_separators)

        self.filter_subrules = filter_subrules
        has_rules_token = lambda rtokens,source_tokens: any([token in source_tokens for token in rtokens])
        has_db_rules_token = lambda rt: has_rules_token(rt, rule_token_to_db_lookup.interpreable_root_tokens)
        has_scapy_rules_token = lambda rt: has_rules_token(rt, rule_token_to_scapy_translation_layer.interpreable_root_tokens)

        self.subrules = subrules

        while self._contains_nested_subrules():
            rules_with_subrules = filter_subrules(subrules)
            #print(f"Parsing out subrules in {rules_with_subrules}")
            for i,subrule in enumerate(rules_with_subrules):
                if any([seperator in subrule for seperator in separators]):
                    #print(f"Embedding rule instance for {subrule}")
                    subrules[i] = rule(subrule, rule_embed_depth=rule_embed_depth+2)
            self.subrules = subrules
            #print(f"Checking if rules has subrules: {self._contains_nested_subrules()}")

        if any([comparator in srule for srule in self.rules_by_separators if srule for comparator in comparators]):
            self.rules_by_comparators = [
                rule_parser.alienate_comparators(rule)
                for rule in self.rules_by_separators
            ]

        self.root_rule = False

        if self.rules_by_comparators:
            self.root_rule = True if not any([isinstance(e, list) for e in self.rules_by_comparators]) else False

        self.root_subrules = []
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

        if self.rules_by_comparators:
            for comparator_rule in self.rules_by_comparators:
                if isinstance(comparator_rule, list):
                    for token in rule_token_to_scapy_translation_layer.interpreable_root_tokens:
                        for rule_token in comparator_rule:
                            if token in rule_token and not any([seperator in ''.join(comparator_rule) for seperator in separators]):
                                logger.debug(f"Translating rule token {rule_token} from {comparator_rule}")
                                translated_rule = rule_token_to_scapy_translation_layer.translate_tokenized_condition(comparator_rule)
                                logger.debug(f"Adding {translated_rule}")
                                self.translated_rules.append(
                                    translated_rule
                                )
                                self.packet_conditions.append(translated_rule)
                                if seperator_index < len(self.rules_by_separators)-1:
                                    self.translated_rules.append(self.rules_by_separators[seperator_index])
                                    seperator_index+=1

                if not rule_parser.has_any_seperable(comparator_rule):
                    root_tokens = comparator_rule.split('.')

                    logger.debug(f"Checking if db_lookup rule: {comparator_rule}")
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

                    logger.debug(f"Checking if scapy rule: {comparator_rule}")
                    if has_rules_token(root_tokens, rule_token_to_scapy_translation_layer.interpreable_root_tokens):
                        rule_translation = rule_token_to_scapy_translation_layer.translate_tokenized_condition([comparator_rule])
                        self.translated_rules.append(
                            rule_translation
                        )
                        self.packet_conditions.append(rule_translation)
                        if seperator_index < len(self.rules_by_separators)-1:
                            self.translated_rules.append(self.rules_by_separators[seperator_index])
                            seperator_index+=1

        for subrule in self.subrules:
            if isinstance(subrule, rule):
                for subrule_translated in subrule.translated_rules:
                    if subrule_translated == "": subrule_translated = "("
                    logger.debug(f"Added {subrule_translated}")
                    self.translated_rules.append(subrule_translated)

        if suffix_rule_parenthesis:
            self.translated_rules.append(")")

        #print(f"~~~~~New Translated Rules: {self.translated_rules}")

        self._translated_rule = ''.join(self.translated_rules)


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


class config_cls:
    config_keys = ['f2b', 'knock', 'custom_handler', 'notify', 'whitelist']
    
    def __init__(self):
        self._whitelist = []
        self._fail2ban = None
        self._knock_daemon = None
        self._custom_handlers = None
        self._notify_methods = None
        self.nftm = netfilter_manager()
        self.enacted_ban_rule_ids = []

    def skippable(self, pkt:tuple):
        ts, sock, pkt = pkt
        if pkt.haslayer(IP):
            return pkt['IP'].src in self._whitelist
        return False

    def tear_down(self):
        self.restore_prelaunch_nftables_state()
        self.nftm.tear_down()

    def set_key(self, key, value):
        if key == 'whitelist': self._whitelist = value
        if key == 'blacklist': self._whitelist = value
        if key == 'f2b':
            self.set_fail2ban(value)
        if key == 'knock':
            self.set_knock_daemon(value)
        if key == 'custom_handler':
            self.set_custom_handlers(value)
        if key == 'notify':
            self.set_notify_methods(value)

    def action_ban(self, ts, sock, pkt, rule=None):
        if pkt.haslayer(IP):
            logger.colorize(f"Banning host {pkt[IP].src} to FoWLands: violation of rule: {rule._raw}", color="Red")
            logger.debug(f"{rule}")
            logger.debug(f"Packet was {pkt}")
            khd = self.nftm.redirect_to_FoWL_net(pkt[IP].src)
            self.enacted_ban_rule_ids.append(khd)
        else:
            logger.colorize(f"Conditions matched but no IP? (for pkt:\n {pkt})")

    def restore_prelaunch_nftables_state(self):
        self.nftm.flush_rules()

    def set_fail2ban(self, x):
        self._fail2ban = x
        logger.info(f"Parsing config bannable offenses")
        self.f2b_callbacks = []
        for i,entry in enumerate(x['ban']):
            logger.info(f"    Parsing F2B Rule {i}, parsing rule name: {entry['name']}")
            r = rule(entry['rule'], name=entry['name'], action=self.action_ban)
            #print(r)
            self.f2b_callbacks.append(r)
            # f2b_conditions.append(
            #     rule_parser.parse(entry['rule'])
            # )
            pass
        #print(f"Successfully parsed f2b rules")



    def set_knock_daemon(self, x):
        self._knock_daemon = x

        logger.info(f"Parsing config for knockd")
        self.knock_calls = []
        for i,entry in enumerate(x['unlock_sequences']):
            logger.info(f"    Parsing knockd Rule {i}, parsing rule name: {entry['name']}")
            try:
                if 'action' in entry.keys():
                    function = import_function_handler(entry['action'])
                    rule(entry['rule'], name=entry['name'], action=function)
                    # knock_calls.append(
                    #     function,
                    #     rule_parser.parse(entry['rule'])
                    # )
            except Exception as e:
                raise
        #print(f"Successfully parsed knockd rules")

    def set_custom_handlers(self, x):
        self._custom_handlers = x

        logger.info(f"Parsing config for injectable-traffic/handlers")
        self.custom_calls = []
        for i,entry in enumerate(x):
            logger.info(f"    Parsing respond Rule {i}, parsing rule name: {entry['name']}")
            try:
                function = import_function_handler(entry['with'])
                if function:
                    #print(rule(entry['rule'])) if 'rule' in entry.keys() else lambda x: True
                    self.custom_calls.append(
                        rule(entry['rule'], name=entry['name'], action=function) if 'rule' in entry.keys() else lambda x: True
                    )
                    continue
                #print(f"Failed to identify module `{module}`")
            except Exception as e:
                raise
        #print(f"Successfully parsed callback/injection handlers")


    def set_notify_methods(self, x):
        self._notify_methods = x

        logger.info(f"Parsing config methods to notify")
        self.notify_calls=[]
        for i, entry in enumerate(x):
            # if entry['method'] in _cls._native_notify_methods.keys():
            #     print(f"    Parsing notify Rule {i}, parsing rule name: {entry['name']}")
            #     notify_calls.append((
            #         _cls._native_notify_methods[entry['method']],
            #         #print(rule(entry['rule']))
            #         # rule_parser.parse(entry['rule'])
            #     ))
            # else:
            function = import_function_handler(entry['with'])
            if function:
                self.notify_calls.append((
                    function,
                #print(rule(entry['rule']))
                    # rule_parser.parse(entry['rule'])
                ))
        #print(f"Successfully parsed notification methods")

class config_parser:
    _native_notify_methods = {'MQTT':notify.mqtt.handler}

    def __init__(self, *args, **kwargs):
        pass

    @classmethod
    def parse_file(*args):
        if len(args) > 2: raise TypeError(f"takes 2 positional argument but {len(args)} were given")
        _cls, path = args
        with open(path,'r') as config:
            config_str = config.read()
        return _cls.parse(config_str)

    @classmethod
    def parse(*args) -> dict:
        if len(args) > 2: raise TypeError(f"takes 2 positional argument but {len(args)} were given")
        _cls, content = args
        cfg = json.loads(content)

        config = config_cls()

        for key in config.config_keys:
            config.set_key(key, cfg[key])

        return config


if __name__ == '__main__':
    try:
        cfg = config_parser.parse_file('FOWLWALL.JSON')
        #print(f"Final result of config: {cfg}")
    except Exception as e:
        #print('\n'.join(format_exception(e)))
        pass
