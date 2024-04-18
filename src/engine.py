from time import sleep
from datetime import datetime, timedelta

from threading import Thread
from queue import Queue, Empty as QueueEmptyException
import queue
import traceback
from scapy.all import *
import inspect
from uuid import uuid4

from my_logger import Logger_Base
from scapy_handler import handle, Unhandled_Scapy_Type

class engine_exit:
    def __init__(self, reason="Caller did not declare an exit reason"): 
        self.reason = reason

class engine_exit_notify:
    def __init__(self, exception=None, reason="Engine reporting that it quit, without reason"): 
        self.exception = exception
        self.reason = reason

class EngineException(Exception):
    def __init__(self, message):
        super().__init__(message)

class engine(Thread):
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        logger_name = kwargs.pop('logger_name',
            f"engine_{self.__class__.__name__}_{uuid4()}"
        )
        self.app_args = kwargs.pop('app_args', None)
        self.args=args

        self.logger=Logger_Base(name=logger_name)
        self.logger.info("Engine has started!")
        if self.app_args and self.app_args.debugging:
            self.logger.enable_debug()
            self.logger.debug("with debugging!")
            self.logger.debug(f"{self.app_args}")

    def stop(self, reason=engine_exit(), timeout=timedelta(seconds=10)):
        if self.iq:
            self.iq.put(reason)
        else:
            if self.logger:
                self.logger.warn("The engine cannot be stopped! It has no input queue!")
            else:
                print(f"The engine({__class__.name}) cannot be stopped! It has no input queue!")

    def get_engine_message(self):
        if self.check_sum_queue_size():
            if self.oq and self.oq.qsize()>0:
                return self.check_output_queue()
            if self.eq and self.eq.qsize()>0:
                return self.check_error_queue()

    def check_sum_queue_size(self):
        return self.oq.qsize()+self.eq.qsize()

    def check_output_queue(self):
        try:
            return self.oq.get_nowait()
        except queue.Empty:
            pass

    def check_error_queue(self):
        try:
            return self.eq.get_nowait()
        except queue.Empty:
            pass

    @staticmethod
    def start_engine(c, *args, **kwargs):
        return c.__class__.start_engine(*args, **kwargs)

    @staticmethod
    def _init_queues():
        return (Queue(), Queue(), Queue())

    def process_pkt(self, p):
        if self.iq:
            self.iq.put(p)
        if not self.iq and self.logger and not hasattr(self, 'engine_logging_exceptions_disabled_has_been_warned'):
            self.logger.warn("Engine is unable receive packets, no input queue")

    def log_operations(self):
        while self.check_sum_queue_size() > 0:
            if self.logger:
                if self.oq and self.oq.qsize()>0:
                    self.logger.info(f"Engine out queue(items:{self.oq.qsize()}: {self.oq.get()}")
                if self.eq and self.eq.qsize()>0:
                    self.log_exceptions()
            else:
                print("engine can't do log_operations :'[")

    def log_exceptions(self):
        try:
            if self.eq and self.eq.qsize()>0:
                e = self.eq.get()
                while e:
                    self.logger.exception(f" Main reads engine exception: {e}", stack_info=True)
                    e = self.eq.get()
            if not self.eq and self.logger and not hasattr(self, 'engine_logging_exceptions_disabled_has_been_warned'):
                self.engine_logging_exceptions_disabled = True
                self.logger.warn("Engine is unable to log, nor report errors")
        except QueueEmptyException as e:
            pass
        except Exception as e:
            self.logger.exception(e)

class realtime_engine(engine):
    def __init__(self, *args, **kwargs):
        self.callbacks=None
        self.database = kwargs.pop('database', None)
        super().__init__(*args, logger_name='realtime_engine', **kwargs)
        pass

    def start_engine(self, *args, **kwargs):
        self.logger.debug("Starting realtime_engine")

        if not 'iq' in kwargs.keys() \
           and not 'oq' in kwargs.keys() \
           and not 'eq' in kwargs.keys():
                io = self._init_queues()
                self.iq, self.oq, self.eq = io
        else:
            self.iq, self.oq, self.eq = (kwargs['iq'], kwargs['oq'], kwargs['eq'])


        try:
            return Thread(target=self.run, args=(self.iq, self.oq, self.eq, args), kwargs=kwargs).start()
        except:
            self.logger.exception("Error starting engine process", stack_info=True, exc_info=True)
            return 

        self.logger.debug("Started realtime_engine")

    def add_callback(self, call=None, conditions=[]):
        if call and conditions:
            self.callbacks.append(call, conditions)

    def run(self, iq, oq, eq, *args, logger=None, callback=None, **kwargs):
        iq_cntr = 0
        in_o = None
        exit_notify = engine_exit_notify(
                exception=EngineException("UndefinedEngineException"),
                reason=None
        )
        def safe_exit(exception, reason="undefined"):
            exit_notify = engine_exit_notify(
                    exception=exception,
                    reason=f"Exiting as instructed, with engine_exit reason:\n\t\t{reason}"
            )
            oq.put(exit_notify)


        try:
            while not isinstance(in_o, engine_exit):
                try:
                    in_o = iq.get_nowait()
                except queue.Empty:
                    sleep(0.003)
                    continue

                if isinstance(in_o, engine_exit):
                    safe_exit(engine_exit, reason=in_o.reason)
                    continue #To next iteration, where exit condition is satisfied


                try:
                    if callback:
                        callback(in_o, *args, database=self.database, **kwargs)
                        continue

                    handle(in_o, *args, logger=self.logger, database=self.database, **kwargs)
                except Exception as e:
                    #If we should *not* report this:
                    if hasattr(self, 'app_args') and self.app_args.suppress_handler and \
                        not hasattr(self, 'app_args') and self.app_args.crash_on_exception:
                        self.logger.debug(f"Engine passing over: {type(e)} {e}")
                    else:
                        self.eq.put(e)
                        if hasattr(self, 'app_args') and self.app_args.crash_on_exception:
                            if isinstance(e, Unhandled_Scapy_Type):
                                self.logger.warn("Exiting safely as configured")
                                #self.logger.exception(e)
                                safe_exit(e, reason=f"A handler, well, did not handle - and the exception({e.__class__}) was raised, as was configured.")
                            else:
                                raise e
                in_o = None
        except Exception as e:
            self.eq.put(e)
            if self.logger:
                self.logger.exception(f"Engine unhandled error: {e}")
                if hasattr(self, 'app_args') and (self.app_args.debugging \
                    or self.app_args.crash_on_exception):
                    self.logger.warn("Exiting as configured")
            safe_exit(e, reason="Internal engine failure")

        if self.logger and exit_notify.reason:
            self.logger.info(exit_notify.reason)
        elif self.logger:
            self.logger.debug(f"There *should* be a stack trace... if not an exit reason.")

class data_store_engine(engine):
    def __init__(self):
        pass

