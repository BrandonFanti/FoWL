from sys import argv, path
path.append('src')


#Logging/debug depends
from time import sleep
from datetime import datetime, timedelta
ts = datetime.now
import pdb
from os import mkdir, geteuid
from sys import argv as app_args
from lazy_logger import bcolors

#Network+Scapy stuff
import socket, sys, time
from scapy import supersocket
from scapy.all import *
from scapy.layers.http import *
from scapy.sessions import DefaultSession

# Run/Config stuff
from dotenv import load_dotenv #evaluate this project
load_dotenv()
from os import environ as env
import signal

"""
This file initializes socket instances, then configures and starts:
 - a database backend
 - an engine
Then simply polls the sockets and passes them along to the engine.
"""


try:
    #Mine
    from argument_parser import FOWL_Argument_Parser, FOWL_Firewall_Setup
    from engine import realtime_engine, engine_exit, engine_exit_notify
    from database import RAM_CACHE
    from lazy_logger import Logger_Base 
    from misc import timeit
    from scapy_handler import Unhandled_Scapy_Type
    from iproute_detection import get_interface_info

    #     -----------------------------------------------------------------------------------------------         #
    #  Logging, configuration, pre-checks, sockets defined here

    name = "FOWL_main"
    start = ts()
    log_file=f"log/{name}-Sess-{ts()}.log"

    logger=Logger_Base(name=name, file_path=log_file)
    logger.info("logger started")

    if '-d ' in app_args or '--debugging ' in app_args:
        logger.enable_debug()

    fowl_args = FOWL_Argument_Parser()
    fowl_args.cli_parse() #Testing

    HOST = fowl_args.address 

    #When lazy
    def print(msg, *k, **kw):
        logger.info(msg, *k, **kw)

    rengine = None
    rdb = None
    def safe_exit(stop_rengine=True, reason=None):
        if rengine and stop_rengine:
            rengine.stop(
                engine_exit(
                    reason=reason
                )
            )
        if socks: #Files don't wear socks
            for sock in socks:
                sock.close()
        if rdb: rdb.save(force=True)
        sys.exit(0)

    socks=None
    pcaps=None
    packets=None
    if fowl_args.file:
        print(fowl_args.file)
        pcaps = iter([rdpcap(f) for f in fowl_args.file])
        packets = iter(next(pcaps))
    else:
        if not geteuid() == 0:
            logger.error("Running as non-uid-0 (AKA root) users is currently not implemented") #TODO: Make this untrue!
            logger.info("Exiting...")
            exit()

        logger.info(" > Setting up socket(s)")
        interfaces = get_interface_info(debug=fowl_args.debugging)


        conf.use_pcap = True    #packet engine, from one of those stupid `from scapy import *`  
        socks = []
        try:
            for i in interfaces.keys():
                logger.debug(f"Listening to interface {i}")
                socks.append(supersocket.L2ListenTcpdump(i, '-l', filter=fowl_args.pcap_filter))
            # socks.append(supersocket.L3RawSocket(promisc=True))
        except Exception as e:
            #TODO: Implement dumpcap for wireshark group users? -
            # scapy doesn't support this directly, but something like
            # dumpcap -> pcap file / period, then scapy just loads the pcap - super inefficient, to a simple start
            # (content injection is implied to not work like this)
            logger.exception(e) 
            logger.info(f"{bcolors.FAIL}Exception initializing SuperSocket(s){bcolors.ENDC} - Exiting")
            exit()
        logger.debug(f"  ... took {logger.timedelta_fmt(ts()-start)}") 

    #     -----------------------------------------------------------------------------------------------         #
    # Next, define our "database", the realtime engine, signal handlers, and some top-level functions

    # "minor" problem- database isn't recording... when debug is enabled. Likely due to multiple processes using it for logs
    rdb = RAM_CACHE(app_args=fowl_args) #Ram cache works in the same process, *hopefully* that doesn't slow things down too much,
    #even still with that: #TODO: Add multithreading for this

    if not fowl_args.file:
        rdb.set_key('origin_host_interfaces', interfaces)
    else:
        rdb.set_key('origin_host_interfaces', [])


    start=ts()
    min_log_main = start+timedelta(seconds=60) #A minimum log interval, so if there's no packets, we know its running
    logger.info("Starting packet capture")

    #Packet processing (coprocess(es))
    rengine = realtime_engine(app_args=fowl_args, database=rdb)
    rproc = rengine.start_engine()

    def interrupt_handler(sig, frame):
        logger.info("CTRL+C detected: Saving and shutting down...")
        safe_exit(reason="User interrupted")

    signal.signal(signal.SIGINT, interrupt_handler)

    # @timeit
    def get_packet() -> (datetime, supersocket.SuperSocket, packet.Packet) or None:
        try:
            s = supersocket.SuperSocket.select(socks)
            if len(s) == 0: return 

            return (ts(), s[0], s[0].recv()) #tuple: (Timestamp, socket, packet)
        except Exception as e: #Shouldn't happen
            logger.exception(f"main.get_packet() is illiterate? Last packet: {pkt}: {e}")
            exit() #SHOULDN"T HAPPEN....

    #Log for the main while-loop
    # @timeit
    def do_logs(pkt_ts):
        logger.time_to_process(ts()-pkt_ts, task_name=f"(#{pkt_cntr}) Packet Processing")
        rengine.log_operations()

    #     -----------------------------------------------------------------------------------------------         #
    # Finally, the polling/consumer loop

    pkt_ts = None
    pkt_cntr = 0
    max_capture_period = ts()+timedelta(seconds=300)

    try:
        while ts()<max_capture_period or fowl_args.no_timeout:
            sleep(0.001)
            try:
                if not fowl_args.file:
                    p = get_packet()
                else:
                    p = (ts(), None, next(packets))
                if min_log_main < ts():
                    min_log_main = ts()+timedelta(seconds=60)
                    print(f"Packet polling loop is still running, \" last packet\": {p}")
                if not p: #No packets?
                    m = rengine.get_engine_message()
                    if not m: continue

                    if isinstance(m, engine_exit_notify) or isinstance(m, Unhandled_Scapy_Type):
                        trace=None
                        if isinstance(m, engine_exit_notify):
                            logger.warn(f"The engine appears to have stopped, reason:\n\t{m.reason}")
                            trace=m.exception
                        if trace and not fowl_args.suppress_handler:
                            logger.warn(f"Handler crash: ")
                            logger.error(trace.trace)
                            logger.warn(f"crash from packet: ")
                            logger.info(trace.packet_dump)
                            safe_exit(reason="Your own actions")

                    if isinstance(m, Unhandled_Scapy_Type):
                        if not fowl_args.suppress_handler:
                            logger.warn(f"Handler crash: ")
                            logger.info(m.source_file_dot_function)
                            logger.warn(f"crash from packet: ")
                            logger.info(m.packet_dump)

                        if fowl_args.crash_on_exception:
                            logger.debug(f"Exiting... {m}")
                            safe_exit(reason="Your handler")

                    if isinstance(m, Exception):
                        logger.warn(f"Engine exception reported: {m.__class__}")
                        logger.exception(m)
                        if fowl_args.crash_on_exception:
                            logger.debug(f"Exiting... {m}")
                            safe_exit(reason="Unhandled internal message")

                    #Not technically an exception... but an unhandled message should *probably* be treated as one
                    if fowl_args.crash_on_exception:
                        logger.warn(f"Exiting... {m}")
                        safe_exit(reason="Unhandled internal message")
                    continue

                #Process the pkt
                pkt_ts, sock, pkt = p
                rengine.process_pkt(p)
                pkt_cntr+=1

            except StopIteration:
                try:
                    packets = iter(next(pcaps))
                except:
                    safe_exit(reason="No more packets.")

            # TODO: What is---------------------------------------|-Not me
            #                                                    V
            #/lib/python3.11/site-packages/scapy/utils.py", line 1337, in fileno
            #    return -1 if WINDOWS else self.f.fileno()
            #                              ^^^^^^^^^^^^^^^
            #ValueError: I/O operation on closed file
            except ValueError:
                safe_exit(reason="Socket closed?")
            except Exception as e:
                logger.exception(f"Couldn't process {pkt}: {e}")
        logger.info("Gracefully exiting with timeout")
        safe_exit()
    except Exception as e:
        logger.exception(f"Exiting, exception in main loop: ({e})")
except Exception as e:
    logger.warn("Failed to start - at all")
    logger.exception(e)


safe_exit() #Don't think we need this, but just in case...
