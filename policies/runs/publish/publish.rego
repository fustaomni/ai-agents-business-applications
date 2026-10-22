# METADATA
# title: publish
# description: Publication is judged from declared expectations, the verdict recomputed (D.178).
package runs.publish

import rego.v1

_ran contains name if some name in input.publish.passed_tests

_ran contains name if some name in input.publish.warned_tests

_ran contains name if some name in input.publish.failed_tests

_passed contains name if some name in input.publish.passed_tests

_expected contains name if some name in input.publish.expected

# METADATA
# title: The publish evidence is supplied, never assumed
# custom:
#   code: ERR_PUBLICATION_INPUT_MISSING
deny contains denial if {
	not input.publish
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no publish evidence: an absent record would read as nothing failing",
	}
}

# METADATA
# title: Publication declares the gates it requires
# custom:
#   code: ERR_PUBLICATION_NOTHING_EXPECTED
deny contains denial if {
	count(input.publish.expected) == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no gate is declared for publication: nothing required is not everything passing",
	}
}

# METADATA
# title: Every declared gate ran on the snapshot
# custom:
#   code: ERR_PUBLICATION_GATE_UNOBSERVED
deny contains denial if {
	some name in input.publish.expected
	not name in _ran
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v is declared and has no result on the snapshot", [name]),
	}
}

# METADATA
# title: No gate failed on the snapshot
# custom:
#   code: ERR_PUBLICATION_GATE_FAILED
deny contains denial if {
	some name in input.publish.failed_tests
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v failed or timed out on the snapshot", [name]),
	}
}

# METADATA
# title: The passed gates are exactly the declared gates
# custom:
#   code: ERR_PUBLICATION_PASSED_SET_MISMATCH
deny contains denial if {
	_passed != _expected
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("passed %v, declared %v", [sort(_passed), sort(_expected)]),
	}
}
