from argparse import RawTextHelpFormatter, Action, ArgumentParser, BooleanOptionalAction
from lazy_logger import bcolors
from os import environ as env

from lazy_logger import Logger_Base

class FOWL_Firewall_Setup(Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print('%r %r %r' % (namespace, values, option_string))
        setattr(namespace, self.dest, values)


class Argument:
    def __init__(self, *args, **kwargs):
        kws = kwargs.keys()
        assert 'name' in kws
        assert 'type' in kws
        assert 'value' in kws
        for key in kwargs:
            setattr(self, key, kwargs[key])

class FOWL_Argument_Parser(ArgumentParser):
    defaults = {
        'setup_firewall': False,
        'fowl_firewall_config_path': None,
        'no_timeout': False,
        'pcap_filter': "",
        'file': None,
        'injection': False,
        'address': '0.0.0.0',
        'ports': ['0'],
        'debugging': False,
        'crash_on_exception': False, #debugging will also set this
        'suppress_handler': False,
        'to_be_overridden': False
    }

    def __init__(self, *k, **kw):
        # Move these to FOWL.py?
        #     -----------------------------------------------------------------------------------------------         #


        super().__init__(
            prog="FOWL",
            description="Fog Of War Listener - FOWL - a network traffic inspection and injection tool.",
            epilog="""

    ~ A tool created by Brandon Fanti ~

Thanks for checking out my project.""",
            formatter_class=RawTextHelpFormatter
        )
        #     -----------------------------------------------------------------------------------------------         #


        #     -----------------------------------------------------------------------------------------------         #
        # *** May want to take this to an intermediary (between ArgumentParser and this) class?     *** #
        # Reason: There seems to be no consensus on load order 
        #       intuitively (to me): POSIX enforces the "configuration->environment->command line" 
        #                            application order systematically for the utilities covered by it.

        #A (briefly) used logger
        if 'logger_name' in kw: logger_name = kw['logger_name']
        else: logger_name = f"argument_parser"
        self.logger=Logger_Base(name=logger_name, log_level=20) #level 20 is info


        #initialize defaults
        self._set_defaults()
        self._add_default_arguments()

        self.to_be_overridden = True # Prevent warnings/prompts in initialization.
        self.environ_parse() #environ vars are overridden by cli_parse() as a default
        self.cli_parse() 
        self.to_be_overridden = False
        self.action_defaults = None


        # *** May want to take this to an intermediary (between ArgumentParser and this) class?     *** #
        #     -----------------------------------------------------------------------------------------------         #



    def _set_defaults(self):
        #Needed in xxx_parse() - if removing parsers in __class__.__init__(),
        # (and __class__'s implementor doesn't call it -- I could see myself here.) 
        defaults = __class__.defaults
        for key in defaults.keys():
            self.logger.debug(f"Setting self.{key} = {defaults[key]}")
            setattr(self, key, defaults[key])

    def _warn_overloading_non_default_and_configured(self, new_options, option_source="?"):
        defaults = __class__.defaults
        to_be_overridden = []
        #Iterate current options and CLI arguments
        for key in new_options.keys():
            #If the default argument is already set in this parser instance, and is not the default
            if hasattr(self, key) \
               and key != getattr(self,key) \
               and key != __class__.defaults[key]:
                to_be_overridden.append((key, new_options[key]))
                if not self.to_be_overridden:
                    self.logger.warn(f"Overriding non-default, previously configured, configuration option: (source: {option_source}) '{key}' \
(Provided: '{new_options[key]}',  (default is {defaults[key]})"
                    )

        if not self.to_be_overridden and to_be_overridden != []:
            self.logger.info("Set --to-override (CLI), or to_override=True (Either .env config file, or environment variable) \
to dismiss these warnings and prompts... alternatively, remove the duplicate"
            )
            if input('Continue with these options? [y/n]: ').upper()[0] == 'N':
                self.logger.info('Exiting...')
                exit()

        for attr,value in to_be_overridden:
            setattr(self, attr, value)

        if not getattr(self, 'debugging', True):
            self.logger.set_level(20) #default log off
        else: self.logger.set_level(10) #Debug on

    #Env, take 3
    def environ_parse(self):
        new_options = {}
        for key in __class__.defaults.keys():
            if key in env: 
                new_options[key] = env[key]

        self._warn_overloading_non_default_and_configured(new_options, option_source="environment")

    #Env, take 2
    def environ_parse_old(self):
        defaults = __class__.defaults
        to_be_overridden = []
        #Iterate current options and environment configured values
        for def_key in __class__.defaults.keys():
            
            #If the default argument is already set in this parser instance, and is not the default, add and warn
            if def_key in env and hasattr(self, def_key) \
               and env[def_key] != __class__.defaults[def_key] \
               and env[def_key] != getattr(self,def_key):
                to_be_overridden.append((def_key, env[def_key]))
                if not self.to_override:
                    self.logger.warn(f"Overriding non-default, previously configured, configuration option \
'{def_key}' with '{env[def_key]}' (default is {defaults[def_key]})"
                    )

        if not self.to_override and to_be_overridden != []:
        #     -----------------------------------------------------------------------------------------------         #
            self.logger.info("Set --to-override (CLI), or to_override=True (Either .env config file, \
                or environment variable) to dismiss these warnings AND prompts.\n\
                Alternatively - remove the duplicate option"
            )
            if input('Continue with these options? [y/n]: ').upper()[0] == 'N':
                self.logger.info('Exiting...')
                exit()

        for option in to_be_overridden:
            attr,value = option
            setattr(self, attr, value)

    def cli_parse(self):
        new_options = {}
        args = self.parse_args()
        self.logger.debug(args)
        #Iterate options 
        for key in vars(args).keys():
            self.logger.debug(f"cli_parse(): Checking {key}")
            if not hasattr(self, key) and getattr(args, key) != __class__.defaults[key]:
                self.logger.debug(f"Changing {key} to  {getattr(args, key)}")
                new_options[key] = getattr(args, key)
            else:
                setattr(self, key, getattr(args, key))
                pass

        self._warn_overloading_non_default_and_configured(new_options, option_source="CLI Flag")

    def cli_parse_old(self):
        defaults = __class__.defaults
        to_be_overridden = []
        args = self.parse_args()
        self.logger.info(args)
        #Iterate options 
        for def_key in __class__.defaults.keys():
            #If the default argument is already set in this parser instance, and is non-default
            if hasattr(self, def_key) \
               and def_key != __class__.defaults[def_key] \
               and def_key != getattr(args,def_key):
                to_be_overridden.append((def_key, getattr(self, def_key)))
                if not self.to_override:
                    self.logger.warn(f"Overriding non-default, previously configured, configuration option '{def_key}' with \
                        '{cli_arg}' (default is {defaults[def_key]})"
                    )

        if not self.to_override and to_be_overridden != []:
            self.logger.info("Set --to-override (CLI), or to_override=True (Either .env config file, or environment variable) \
                to dismiss these warnings and prompts.\n\
                Alternatively - remove the duplicate"
            )
            if input('Continue with these options? [y/n]: ').upper()[0] == 'N':
                self.logger.info('Exiting...')
                exit()

        for arg in to_be_overridden:
            attr,value = arg
            setattr(self, attr, value)


    def _add_default_arguments(self):
        if hasattr(self, 'action_defaults'):
            self.logger.debug("Resetting argparser Action defaults")
        defaults = __class__.defaults
        actions = []

        actions.append(
            self.add_argument(
                "--fowl-wall-config", 
                dest="fowl_firewall_config_path", 
                action='store', default=None
            )
        )

        actions.append(
            self.add_argument(
                "--setup-firewall", 
                help=f'''Setup firewall rules to DROP traffic, and allow us to respond over the raw sockets
                    {bcolors.WARNING}WARNING: This {bcolors.FAIL}WILL WIPE{bcolors.WARNING} existing rules, and is not persistent (in itself) {bcolors.ENDC}''',
                dest="setup_firewall", action='store_true', default=defaults['setup_firewall']
            )
        )

        actions.append(
            self.add_argument(
                "--no-timeout", 
                help=f"Disables the default capture window of 5 minutes",
                dest="no_timeout", action='store_true', default=defaults['no_timeout']
            )
        )

        actions.append(
            self.add_argument(
                "-f",
                "--pcap", 
                dest="file",
                action="append",
                type=str, default=defaults['file'],
                help="Analyze pcap file(s)"
            )
        )


        actions.append(
            self.add_argument(
                "--pcap-filter", 
                help=f'Apply a custom pcap-filter to constrain traffic FoWL receives - for more info, run `man pcap-filter`',
                dest="pcap_filter", action='store', default=defaults['pcap_filter']
            )
        )

        actions.append(
            self.add_argument(
                "-i",
                "--inject", 
                dest="injection", action='store_true', default=defaults['injection'],
                help="Use root privileges (raw socket(s)) to inject response traffic"
            )
        )

        actions.append(
            self.add_argument(
                "-v",
                "--debugging",
                dest="debugging", action='store_true', default=defaults['debugging'],
                help="Maximize log verbosity"
            )
        )

        actions.append(
            self.add_argument(
                "--crash-on-handler-exception",
                dest="crash_on_exception", action='store_true', default=defaults['crash_on_exception'],
                help="useful for debugging custom handler exceptions raised by an engine"
            )
        )

        actions.append(
            self.add_argument(
                "--suppress-handler-unhandled",
                dest="suppress_handler", action='store_true', default=defaults['suppress_handler'],
                help="useful for debugging custom handler exceptions raised by an engine"
            )
        )

        actions.append(
            self.add_argument(
                "-l",
                "--bind-address",
                dest="address",
                type=str, default=defaults['address'],
                help="Which source addresses to listen/inject/respond from/on"
            )
        )

        actions.append(
            self.add_argument(
                "-p",
                "--listen-ports",
                dest="ports",
                type=lambda t: [s.strip() for s in t.split(',')],
                default=defaults['ports'],
                help="Which destination ports to listen/inject/respond from"
            )
        )

        self.action_defaults = actions
