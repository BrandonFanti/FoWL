from sys import argv, path
path.append('src')
path.append('.')

import json
from importlib import import_module
import inspect
from traceback import format_exception
import notify

from .netfilter_manager import netfilter_manager
from .rule import rule, WarnConfigParserError

import re
from datetime import datetime, timedelta
ts = datetime.now

from lazy_logger.my_logger import Logger_Base
name = "FOWL_WALL_RULE_PARSER"
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

        self.f2b_callbacks = []
        self.knock_calls = []
        self.notify_calls=[]
        self.custom_calls = []

    def skippable(self, pkt:tuple):
        ts, sock, pkt = pkt
        if pkt.haslayer(IP):
            return pkt['IP'].src in self._whitelist
        return False

    def tear_down(self):
        self.restore_prelaunch_nftables_state()
        self.nftm.tear_down()

    def set_key(self, key, value):
        try:
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
        except WarnConfigParserError as e:
            self.nftm.tear_down()
            raise e

    def action_ban(self, ts, sock, pkt, rule=None):
        if self.nftm.in_FoWLands(pkt[IP].src): return
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
        for i,entry in enumerate(x['ban']):
            logger.info(f"    Parsing F2B Rule {i}, parsing rule name: {entry['name']}")
            if 'with' in entry.keys():
                r = rule(
                    entry['rule'], 
                    name=entry['name'], 
                    action= import_function_handler(entry['with'])
                )
                self.f2b_callbacks.append(r)

                logger.debug(f"Translated rule(raw): {r._raw}")
                logger.debug(f"Translated rule: {r._translated_rule}")

            # f2b_conditions.append(
            #     rule_parser.parse(entry['rule'])
            # )
            pass
        #print(f"Successfully parsed f2b rules")



    def set_knock_daemon(self, x):
        self._knock_daemon = x

        logger.info(f"Parsing config for knockd")
        for i,entry in enumerate(x['unlock_sequences']):
            logger.info(f"    Parsing knockd Rule {i}, rule name: {entry['name']}")
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
        for i,entry in enumerate(x):
            logger.info(f"    Parsing respond Rule {i}, rule name: {entry['name']}")
            try:
                function = import_function_handler(entry['with'])
                if function:
                    #print(rule(entry['rule'])) if 'rule' in entry.keys() else lambda x: True
                    self.custom_calls.append(
                        rule(entry['rule'], name=entry['name'], action=function) if 'rule' in entry.keys() else lambda x: True
                    )
                    logger.debug(f"Translated rule(raw): {self.custom_calls[-1]._raw}")
                    logger.debug(f"Translated rule: {self.custom_calls[-1]._translated_rule}")
                    continue
                logger.error(f"Failed to identify module function `{entry['with']}`")
            except Exception as e:
                raise
        #print(f"Successfully parsed callback/injection handlers")


    def set_notify_methods(self, x):
        self._notify_methods = x

        logger.info(f"Parsing config methods to notify")
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
    _native_notify_methods = {'MQTT':notify.mqtt_handler}

    def __init__(self, *args, **kwargs):
        pass

    @classmethod
    def parse_file(*args):
        if len(args) > 2: raise TypeError(f"takes 2 positional argument but {len(args)} were given")
        _cls, path = args
        with open(path,'r') as config:
            config_str = config.read()
        # logger.debug(f"Parsing string: {config_str}")

        return _cls.parse(config_str)

    @classmethod
    def parse(*args) -> dict:
        if len(args) > 2: raise TypeError(f"takes 2 positional argument but {len(args)} were given")
        _cls, content = args
        cfg = json.loads(content)

        config = config_cls()

        for key in config.config_keys:
            logger.debug(f"Setting key {key}")
            config.set_key(key, cfg[key])

        return config


if __name__ == '__main__':
    try:
        cfg = config_parser.parse_file('FOWLWALL.JSON')
        #print(f"Final result of config: {cfg}")
    except Exception as e:
        #print('\n'.join(format_exception(e)))
        pass
