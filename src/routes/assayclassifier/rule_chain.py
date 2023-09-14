import sys
from rule_engine import Rule

class NoMatchException(Exception):
    pass

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
    def apply(self, rec):
        ctx = {}  # so rules can leave notes for later rules
        for elt in iter(self):
            print(f"applying {elt} to rec:{rec}  ctx:{ctx}")
            rslt, key_to_set, val_to_set = elt.apply(rec | ctx)
            if rslt:
                print(f"returning {rslt}")
                return dict(rslt)
            elif key_to_set:
                print(f"ctx[{key_to_set}] <- {val_to_set}")
                ctx[key_to_set] = val_to_set
        raise NoMatchException(f"No rule matched record {rec}")

class TestRule:
    def __init__(self, rule_str, val_str):
        self.test_rule = Rule(rule_str)
        self.val_rule = Rule(val_str)
    def __str__(self):
        return f"<TestRule({self.test_rule}, {self.val_rule})>"
    def apply(self, rec_dict):
        if self.test_rule.matches(rec_dict):
            return self.val_rule.evaluate(rec_dict), None, None
        else:
            return None, None, None

class NoteRule(TestRule):
    def __init__(self, rule_str, val_str, key):
        super().__init__(rule_str, val_str)
        self.key = key
    def __str__(self):
        return f"<NoteRule({self.test_rule}, {self.val_rule} -> {self.key}>"
    def apply(self, rec_dict):
        if self.test_rule.matches(rec_dict):
            return None, self.key, self.val_rule.evaluate(rec_dict)
        else:
            return None, None, None

chain = RuleChain()
chain.add(TestRule('name=="foo"', "{'assaytype': name}"))
chain.add(NoteRule('name=="bar"', "'bar_type'", "assay_class"))
chain.add(TestRule('assay_class == "bar_type" and othername == "baz"', "{'assaytype': 'baz'}"))

chain.dump(sys.stdout)

for test_case in [{"name":"foo"},
                  {"name":"bar", "othername":"baz"},
                  {"name":"bar", "othername":"blrf"}]:
    print(f"Testing {test_case}")
    print(f"-> {chain.apply(test_case)}")

