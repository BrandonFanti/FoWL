from sys import argv, path
path.append('src')
path.append('.')

import json
from importlib import import_module
import inspect
from traceback import format_exception
import notify

def import_function_handler(reference:str) -> callable or None:
    """ Get a memory-backed function reference
    
        param: reference from a string like "logging.info" (e.g. `import logging; logging.info()`)
        returns: a pointer to the function instance, or None 
    """
    module, funct = reference.split('.')
    print(f"Looking for `{funct}()` in module `{module}`")
    this_module = import_module(module)
    if funct in dir(this_module):
        print(f"Importing `{funct}`")
        funct = this_module.__getattribute__(funct)
        if hasattr(funct,'__call__'):
            del this_module
            return funct
    del this_module
    return 




class WarnConfigParserError(Exception):
    def __init__(self, *args, **kwargs):
        pass


class rule_token_to_scapy_translation_layer:
    STATEMENT_NONE=0
    STATEMENT_BIFURCATES=1
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
        print(f"Translater received token: {token}")
        ctx_evaluable = ''
        if 'device' in token:
            subtokens = token.split('.')
            print('\t'+str(subtokens))
            if subtokens[-1] == 'mac': 
                subtokens[-1]='Ether'
                ctx_lookup = ('[Ether].src','[Ether].dst')
            elif subtokens[-1] == 'ip': 
                subtokens[-1]='IP'
                ctx_lookup = ('[IP].src','[IP].dst')
            ctx_evaluable=f"pkt.hasLayer({subtokens[-1]})"
            return (ctx_evaluable,(_cls.STATEMENT_BIFURCATES, ctx_lookup)) #but also reconverges?

        if 'tcp' in token:
            ctx_evaluable = f"pkt.hasLayer(TCP) and "
            subtokens = token.split('.')
            if subtokens[1] in ('syn','ack','rst','fin'):
                ctx_evaluable += f" pkt[TCP].flags == {subtokens[1][0].upper()} "

        if token.upper() in ('DHCP',):#Replace with statics: _cls.direct_translations[token.upper()]
            ctx_evaluable=f"pkt.hasLayer({token.upper()}) "

        if token[0] == "'" or token[0] == '"':
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

        print(f"translate_condition(): returning new condition : {new_condition}")

        return new_condition


class rule_parser:
    supported_conditional_separators = (" and ", " or ", " && ", " || ")
    supported_conditional_comparators = (" == "," != ", " <= ", " >= ", " > ", " < ")

    def __init__(self, *args, **kwargs):
        pass

    @classmethod
    def alienate(_cls, rule, seperators):
        change = False
        conditionals_split=[rule]
        if any(condition in rule for condition in seperators):
            for condition in seperators:
                for splitt in conditionals_split:
                    if condition in splitt and condition != splitt:
                        print(f"\tSplitting '{splitt}' with '{condition}'")
                        change=True
                        conditionals_split=[token.strip() for token in splitt.split(condition)]
                        conditionals_split.insert(1, condition)
                        break
                break
        else: return rule

        if change: 
            return [_cls.alienate(subtokens, seperators) for subtokens in conditionals_split] 
        return conditionals_split[0]

    @classmethod
    def _tokenizer(*args):
        _cls, rules = args

        all_rule_tokens=[]
        if isinstance(rules, str): rules=[rules]
        for i,rule in enumerate(rules):
            rule = _cls.alienate(rule, _cls.supported_conditional_separators)
            print(f"First pass of separators: {rule}")
            rule = _cls.alienate(rule, _cls.supported_conditional_comparators)
            print(f"Second pass of conditionals: {rule}")


            # rule_tokens = []
            # if any(condition in conditionals_split for condition in _cls.supported_conditional_comparators):
            #     for condition in _cls.supported_conditional_comparators:
            #         if condition in rule_tokens:
            #             rule_tokens = [token.strip() for token in rule_tokens.split(condition)]
            #             rule_tokens.insert(1, condition)
            #             break
            #         else: continue
            # all_rule_tokens.append(rule_tokens)

        print(f"All subconditions tokenized: {all_rule_tokens}")
        #TODO: Lexer?

        rts_stl = rule_token_to_scapy_translation_layer
        new_condition = ""
        for condition in all_rule_tokens:
            print(f"_tokenizer sending condition to ", end='')
            # if not a true condition: translate the token
            if len(condition) <= 1 and isinstance(condition, str): 
                print(f" {condition} translate().")
                new_condition += rts_stl.translate(condition)[0]
                continue
            #If true condition:
            print(f" {condition} translate_tokenized_condition().")
            new_condition += rts_stl.translate_tokenized_condition(condition)
        print(f"_tokenizer returning condition: {new_condition}")
        return new_condition



    @classmethod
    def parse(*args) -> callable:
        print(args)
        _cls, _rule  = args

        print(f"Parsing rule: {_rule}")
        #TODO: finish parenthetical groups like "tcp and (host.src == $x or host.dst == $x)"
        # conditional_groups = rule.find_rule

        discrete_unilateral_conditions = [rule.strip() for rule in _rule.split(' or ')]
        discrete_conditions = [rule.strip() for rule in _rule.split(' and ')]

        print(f"descrete uni cond: {discrete_unilateral_conditions}")
        print(f"descrete cond: {discrete_conditions}")

        print("Running tokenizer")

        print(_cls._tokenizer(_rule))

        rules = []
        # for condition in discrete_conditions:
        #     rules.append(_cls._tokenizer(condition))

        unilateral_rules=[]
        # for condition in discrete_unilateral_conditions:
        #     unilateral_rules.append(_cls._tokenizer(condition))

        print(f"All tokens for rule `{_rule}`: Translate to...")
        for rule in rules:
            print(f"\t\t\t   {rule}")
        for rule in unilateral_rules:
            print(f"\t(unilateral rules):{rule}")

        #TODO: Finish translation layer(rule_token_translation_layer), then this
        return lambda x: True


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
    def parse(*args) -> [(callable, callable)]:
        if len(args) > 2: raise TypeError(f"takes 2 positional argument but {len(args)} were given")
        _cls, content = args
        cfg = json.loads(content)

        #Parse the 4 top-keys: f2b, knock, respond, notify
        f2b, knock, custom, notify = [cfg[k] for k in cfg.keys()]

        print(f"Parsing config bannable offenses")
        f2b_conditions = []
        for i,entry in enumerate(f2b['ban']):
            print(f"Parsing F2B Rule {i}, parsing rule name: {entry['name']}")
            f2b_conditions.append(
                rule_parser.parse(entry['rule'])
            )
        print(f"Successfully parsed f2b rules")

        print(f"Parsing config for knockd")
        knock_calls = []
        for i,entry in enumerate(knock['unlock_sequences']):
            print(f"Parsing knockd Rule {i}, parsing rule name: {entry['name']}")
            try:
                if 'action' in entry.keys():
                    function = import_function_handler(entry['action'])
                    knock_calls.append(
                        function,
                        rule_parser.parse(entry['rule'])
                    )
            except Exception as e:
                raise
        print(f"Successfully parsed knockd rules")

        print(f"Parsing config for injectable-traffic/handlers")
        custom_calls = []
        for i,entry in enumerate(custom):
            print(f"Parsing respond Rule {i}, parsing rule name: {entry['name']}")
            try:
                function = import_function_handler(entry['with'])
                if function:
                    custom_calls.append((
                        function,
                        rule_parser.parse(entry['rule']) if 'rule' in entry.keys() else lambda x: True
                    ))
                    continue
                print(f"Failed to identify module `{module}`")
            except Exception as e:
                raise
        print(f"Successfully parsed callback/injection handlers")


        print(f"Parsing config methods to notify")
        notify_calls=[]
        for i, entry in enumerate(notify):
            if entry['method'] in _cls._native_notify_methods.keys():
                notify_calls.append((
                    _cls._native_notify_methods[entry['method']],
                    rule_parser.parse(entry['rule'])
                ))
            else:
                function = import_function_handler(entry['with'])
                if function:
                    notify_calls.append((
                        function,
                        rule_parser.parse(entry['rule'])
                    ))
        print(f"Successfully parsed notification methods")

        return ([*notify_calls, *custom_calls, *knock_calls],f2b_conditions)


if __name__ == '__main__':
    try:
        cfg = config_parser.parse_file('FOWLWALL.JSON')
        print(f"Final result of config: {cfg}")
    except Exception as e:
        print('\n'.join(format_exception(e)))
