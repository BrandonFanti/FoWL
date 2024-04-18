from benedict.dicts import benedict
from my_logger import Logger_Base
from uuid import uuid4
import json
from datetime import timedelta, datetime
class database: #database used loosely here
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        logger_name = kwargs.pop('logger_name',
            f"unnamed_DB_{self.__class__.__name__}_{uuid4()}"
        )
        self.app_args = kwargs.pop('app_args', None)
        self.args=args

        setattr(self, 'logger', Logger_Base(name=logger_name))
        self.logger.info("Database has initialized!")
        if self.app_args and self.app_args.debugging:
            self.logger.enable_debug()
            self.logger.debug("With debugging")

    def get(self, key):
        return NotImplemented

    def set_key(self, key, value):
        return NotImplemented


#Basically, a dict wrapper
class RAM_CACHE(database):
    def __init__(self, *args, **kwargs):
        self.b=benedict()
        self.max_save_interval = timedelta(seconds=15)
        self.last_save = None
        super().__init__(*args, **kwargs)

    def get(self, key):
        return self.b[key]

    def set_key(self, key, value):
        #self.logger.debug(f"Recording {key} -> {value}")
        self.b[key]  = value

    def add_to_key(self, key, value):
        #self.logger.debug(f"Recording {key} -> {value}")
        self.b.setdefault(key,[])
        if value in self.b[key]: return
        self.b[key].append(value)
        self.save()

    def save(self, out_file="data/RAM_CACHE", out_type="JSON", file_extension="", force=False):
        if not force and self.last_save and \
            self.last_save + self.max_save_interval > datetime.now():
            return
        self.last_save = datetime.now()
        output_file = out_file+'.'+out_type+file_extension
        self.logger.debug(f"Saving to JSON -> {output_file}")
        with open(output_file, 'wb') as f:
            match out_type:
                case "JSON":
                    f.write(self.b.to_json().encode('utf-8'))

    def load(self, src_file="data/RAM_CACHE.JSON", src_type="JSON"):
        self.logger.debug(f"Reading JSON -> {src_file}")
        with open(src_file, 'rb') as f:
            match src_type:
                case "JSON":
                    self.b=json.loads(f.read().decode('utf-8'))
