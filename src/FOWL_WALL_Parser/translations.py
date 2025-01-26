from datetime import datetime
ts=datetime.now
from lazy_logger.my_logger import Logger_Base
name = "FOWL_WALL_RULE_TRANSLATOR"
log_file=f"log/{name}-Sess-{ts()}.log"
logger=Logger_Base(name=name, file_path=log_file, log_level=20) #level 20 is info

class rule_token_to_db_lookup:
    interpreable_root_tokens = ['host']

    def translate(token):
        token = token.split('.')
        if 'banned' == token[1]:
            return f"database_cli.get(f\"{token[0]}" + '.{pkt[IP].src.replace(\'.\',\'_\')}.' + f"{token[1]}\")"


class rule_token_to_scapy_translation_layer:
    interpreable_root_tokens = ['device', 'tcp', 'dhcp', 'net']

    STATEMENT_NONE=0        #Direct statement, needs no further manipulation
    STATEMENT_BIFURCATES=1  #Statement was 'OR'
    STATEMENT_CONVERGE=2    #Statement was 'AND'
    STATEMENT_ARG_0=3       #Statement should only use left tuple value
    STATEMENT_ARG_1=4       #Statement should only use right tuple value

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
                ctx_evaluable += f" and '{subtokens[1][0].upper()}' in pkt[TCP].flags"

        if token.upper() in ('DHCP',):#Replace with statics: _cls.direct_translations[token.upper()]
            ctx_evaluable=f"pkt.haslayer({token.upper()})"

        if token != '' and (token[0] == "'" or token[0] == '"'):
            ctx_evaluable=token

        return (ctx_evaluable, (_cls.STATEMENT_NONE, None))

    @classmethod
    def translate_boolean_statement(_cls, statement):
        new_condition,other = _cls.translate(statement)

        if _cls.STATEMENT_BIFURCATES in other:
            _, ctx_lookup = other
            ctx_lookup, ctx_lookup_alt = ctx_lookup
            new_condition += f" and (pkt{ctx_lookup} "
            new_condition += f" or pkt{ctx_lookup_alt} )"

        if _cls.STATEMENT_CONVERGE in other:
            _, ctx_lookup = other
            ctx_lookup, ctx_lookup_alt = ctx_lookup
            new_condition += f" and (pkt{ctx_lookup} "
            new_condition += f" and pkt{ctx_lookup_alt} )"

        if _cls.STATEMENT_ARG_0 in other:
            _, ctx_lookup = other
            ctx_lookup, _ = ctx_lookup
            new_condition += f" and pkt{ctx_lookup} "
        if _cls.STATEMENT_ARG_1 in other:
            _, ctx_lookup = other
            _, ctx_lookup_alt = ctx_lookup
            new_condition += f" and pkt{ctx_lookup_alt} "

        return new_condition

    @classmethod
    def translate_tokenized_condition(_cls, condition):
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