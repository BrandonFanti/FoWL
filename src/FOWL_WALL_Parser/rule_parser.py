import re
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