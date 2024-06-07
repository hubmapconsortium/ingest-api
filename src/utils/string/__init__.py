import re

# copied from:
# https://github.com/x-atlas-consortia/commons/blob/main/atlas_consortia_commons/string/__init__.py


def _to_case(val: str, case: str) -> str:
    _val = re.sub(r"[^a-zA-Z0-9 ]+", "", val)
    _val = _val.strip().lower()
    if case == 'camel':
        _val = ''.join(x for x in _val.title() if x.isalnum())
        return _val[0].lower() + _val[1:]
    elif case == 'pascal':
        _val = _val.title()
        return _val.replace(' ', '')
    elif case == 'title':
        return _val.title()
    else:
        # snake
        return _val.replace(' ', '_')


def to_title_case(val) -> str:
    return _to_case(val, 'title')


def equals(str1: str, str2: str, insensitive: bool = True):
    res = str1 == str2
    if insensitive is True:
        if str1 is not None and str2 is not None:
            res = str1.lower() == str2.lower()
    return res
