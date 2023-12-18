import unittest
from routes.assayclassifier.rule_chain import RuleChain, RuleLoader, NoMatchException

#
# Running the tests... At the top level directory type 'nose2 --verbose --log-level debug`
#
# WARNING: ONLY methods beginning with "test_" will be considered tests by 'nose2' :-(
class TestAssayClassifier(unittest.TestCase):

    def setUp(self):
        test_rule_yaml = """
        - type: 'match'
          match: 'name == "foo"'
          value: "{'assaytype': name}"
        - type: 'note'
          match: 'name=="bar"'
          value: "{'assay_class': 'bar_type'}"
        - type: 'match'
          match: 'assay_class == "bar_type" and othername == "baz"'
          value: "{'assaytype': 'baz'}"
        """
        self.chain = RuleLoader(test_rule_yaml).load()

    def test_matches(self):
        for test_case, expected_val in [
                ({"name":"foo"}, {'assaytype': 'foo'}),
                ({"name":"bar", "othername":"baz"}, {'assaytype': 'baz'}),
        ]:
            self.assertEqual(self.chain.apply(test_case), expected_val)

    def test_match_fails(self):
        test_case = {"name":"bar", "othername":"blrf"}
        with self.assertRaises(NoMatchException) as context:
            self.chain.apply(test_case)
