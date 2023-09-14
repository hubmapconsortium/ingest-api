import sys
import logging
import yaml
import json
from pathlib import Path
from rule_engine import Rule
from hubmap_commons.schema_tools import check_json_matches_schema

logger: logging.Logger = logging.getLogger(__name__)

SCHEMA_FILE = 'rule_chain_schema.json'
SCHEMA_BASE_URI = 'http://schemata.hubmapconsortium.org/'


class NoMatchException(Exception):
    pass


class RuleSyntaxException(Exception):
    pass


class RuleLoader:
    def __init__(self, stream):
        self.stream = stream
    def load(self):
        rule_chain = RuleChain()
        json_recs = yaml.safe_load(self.stream)
        print(f"PING {json_recs}")
        check_json_matches_schema(json_recs,
                                  SCHEMA_FILE,
                                  str(Path(__file__).parent),
                                  SCHEMA_BASE_URI)
        print('PINGPING')
        for rec in json_recs:
            for rule in [rec[key] for key in ['match', 'value']]:
                assert Rule.is_valid(rule), f"Syntax error in rule string {rule}"
            try:
                rule_cls = {'note': NoteRule,
                            'match': MatchRule}[rec['type'].lower()]
            except KeyError:
                raise RuleSyntaxException(f"Unknown rule type {rec['type']}")
            rule_chain.add(rule_cls(rec['match'], rec['value']))
        return rule_chain


class _RuleChainIter:
    def __init__(self, rule_chain):
        self.offset = 0
        self.rule_chain = rule_chain
    def __next__(self):
        if self.offset < len(self.rule_chain.links):
            rslt = self.rule_chain.links[self.offset]
            self.offset += 1
            return rslt
        else:
            raise StopIteration
    def __iter__(self):
        return self


class RuleChain:
    def __init__(self):
        self.links = []
    def add(self, link):
        self.links.append(link)
    def dump(self, ofile):
        for idx, elt in enumerate(iter(self)):
            print(f"{idx}: {elt}")
    def __iter__(self):
        return _RuleChainIter(self)
    @classmethod
    def cleanup(cls, val):
        """
        Convert val to JSON-appropriate data types
        """
        if isinstance(val, dict): # includes OrderedDict
            return dict({cls.cleanup(key): cls.cleanup(val[key]) for key in val})
        elif isinstance(val, list):
            return list(cls.cleanup(elt) for elt in val)
        else:
            return val
    def apply(self, rec):
        ctx = {}  # so rules can leave notes for later rules
        for elt in iter(self):
            logger.debug(f"applying {elt} to rec:{rec}  ctx:{ctx}")
            rec_dict = rec | ctx;
            if elt.match_rule.matches(rec_dict):
                val = elt.val_rule.evaluate(rec_dict)
                if isinstance(elt, MatchRule):
                    return self.cleanup(val)
                elif isinstance(elt, NoteRule):
                    assert isinstance(val, dict), f"Rule {elt} applied to {rec_dict} did not produce a dict"
                    ctx.update(val)
                else:
                    raise NotImplementedError(f"Unknown rule type {type(elt)}")
        raise NoMatchException(f"No rule matched record {rec}")


class BaseRule:
    def __init__(self, rule_str, val_str):
        self.match_rule = Rule(rule_str)
        self.val_rule = Rule(val_str)


class MatchRule(BaseRule):
    def __str__(self):
        return f"<MatchRule({self.match_rule}, {self.val_rule})>"


class NoteRule(BaseRule):
    def __str__(self):
        return f"<NoteRule({self.match_rule}, {self.val_rule}>"

