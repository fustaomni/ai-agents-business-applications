# METADATA
# title: pr_checks
# description: A declared check with no run is re-requested only from an app suite awaiting one.
package runs.pr_checks

import rego.v1

_missing contains name if {
	some name in input.pr_checks.expected
	not name in input.pr_checks.present
}

_owning contains owner.app if {
	some owner in input.pr_checks.owners
	owner.check in _missing
}

_awaiting contains suite.id if {
	some suite in input.pr_checks.suites
	suite.check_runs == 0
	suite.app in _owning
}

# METADATA
# title: The checks request is supplied, never assumed
# custom:
#   code: ERR_PR_CHECKS_INPUT_MISSING
deny contains denial if {
	not input.pr_checks
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no pr_checks input: an absent request would read as cleared to re-request",
	}
}

# METADATA
# title: There is a pull request
# custom:
#   code: ERR_PR_CHECKS_NO_PR
deny contains denial if {
	input.pr_checks.pr == null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "the branch has no open pull request",
	}
}

# METADATA
# title: A declared check has no run on the head
# custom:
#   code: ERR_PR_CHECKS_NOTHING_MISSING
deny contains denial if {
	input.pr_checks
	count(_missing) == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "every expected check already has a run on the head: there is nothing to recover",
	}
}

# METADATA
# title: An app suite on the head awaits a run
# custom:
#   code: ERR_PR_CHECKS_NO_AWAITING_SUITE
deny contains denial if {
	count(_missing) > 0
	count(_awaiting) == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v have no run and no suite of their app awaits one: it never got the push", [_missing]),
	}
}

# METADATA
# title: Every missing check names the app that owns it
# custom:
#   code: ERR_PR_CHECKS_OWNER_UNDECLARED
deny contains denial if {
	some name in _missing
	not name in {owner.check | some owner in input.pr_checks.owners}
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v declares no owning app: no suite can be chosen for it", [name]),
	}
}
