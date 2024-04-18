import functools
import time

def timeit(f):
    @functools.wraps(f)
    def wrap(*args, logger=None, **kwargs):
        ts = time.time()
        result = f(*args, **kwargs)
        te = time.time()

        keywords_string = ''
        for index, keyword in enumerate(kwargs.keys()):
            keywords_string += keyword+'='+str(kwargs[keyword])
            if index+1 is not len(kwargs.keys()):
                keywords_string += ','

        if not logger: 
            # "I Said we TYPE now"  
            logger=type('i_said_we',(type,),{}) 
            setattr(logger,'debug', print)
            #https://knowyourmeme.com/memes/i-said-we-sad-today

        if result:
            logger.debug(f"  {f.__name__}({args},{keywords_string}) took: {te-ts:3.6f} sec")

        return result
    return wrap

def wut(obj, subtype=None, phelp=False, logger=None) -> None or [str]:
    wut_str = f"wut({obj})"

    if not logger: 
        # "I Said we TYPE now"  
        logger=type('i_said_we',(type,),{}) 
        setattr(logger,'pprint', print)
        #https://knowyourmeme.com/memes/i-said-we-sad-today


    print("*"*10+f"{wut_str}"+"*"*10)
    print(obj)
    if hasattr(obj, '__name__'):
        print("\tName: "+str(obj.__name__))
    if hasattr(obj, '__class__'):
        print("\tClass Name: "+str(obj.__class__))
    print(f"\tType: {type(obj)}")
    if subtype:
        for fld in dir(obj):
            if hasattr(obj, fld):
                fv = eval(f"obj.{fld}")
                ftype=type(eval(f"obj.{fld}"))
                # logger.debug(f"\t(sts) {fld} : {ftype} == {subtype}")
            else: continue
            if ftype==subtype:
                print(f"\t  matched subtype({subtype}): obj.{fld}")
                logger.pprint(fv)
    logger.pprint(dir(obj))
    if phelp: print(str(help(obj)))
    print("*"*15+"*first layer, if iterable")
    try:
        for i in obj: print(i)
    except:
        pass

    print("*"*10+"*"*len(wut_str)+"*"*10)