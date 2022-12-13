import logging

logger: logging.Logger = logging.getLogger(__name__)


def __get_dict_prop(dic, prop_name):
    if prop_name not in dic:
        return None
    val = dic[prop_name]
    if isinstance(val, str) and val.strip() == '':
        return None
    return val
