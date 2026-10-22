# METADATA
# title: Branch protection policy
# description: develop and main keep a required gate pinned to its app, strict and unbypassable.
package runs.check_ruleset

import rego.v1

# THE GATE'S PRODUCER, GitHub Actions: a status of the same name from any other app or token
# cannot satisfy a check pinned to it (D.168).
pinned_app := 15368

required_check := "quality gate"

required_rules := {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}

required_refs := {"refs/heads/develop", "refs/heads/main"}

state := input.ruleset_state

# METADATA
# title: The ruleset state must be observed
# custom:
#   code: ERR_RULESET_INPUT_MISSING
deny contains denial if {
	not state.contract
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "the ruleset state was not observed",
	}
}

# METADATA
# title: The protection ruleset must exist
# custom:
#   code: ERR_RULESET_MISSING
deny contains denial if {
	state.contract
	not state.found
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no ruleset named develop-and-main-protection exists; apply it with repo:configure",
	}
}

# METADATA
# title: The ruleset must be enforced
# custom:
#   code: ERR_RULESET_NOT_ACTIVE
deny contains denial if {
	state.found
	state.enforcement != "active"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("enforcement is %q, not active", [state.enforcement]),
	}
}

# METADATA
# title: Every protecting rule is present
# custom:
#   code: ERR_RULESET_RULE_MISSING
deny contains denial if {
	state.found
	some kind in required_rules
	not kind in state.rule_types
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("missing rule %q", [kind]),
	}
}

# METADATA
# title: Both long-lived branches are covered
# custom:
#   code: ERR_RULESET_REF_UNPROTECTED
deny contains denial if {
	state.found
	some ref in required_refs
	not ref in state.refs
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%q is not protected", [ref]),
	}
}

# METADATA
# title: The quality gate is required
# custom:
#   code: ERR_RULESET_CHECK_NOT_REQUIRED
deny contains denial if {
	state.found
	count([check | some check in state.required_checks; check.context == required_check]) == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%q is not a required check", [required_check]),
	}
}

# METADATA
# title: The quality gate is pinned to its app
# custom:
#   code: ERR_RULESET_CHECK_UNPINNED
deny contains denial if {
	some check in state.required_checks
	check.context == required_check
	check.integration_id != pinned_app
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%q is pinned to %v, not app %v", [check.context, check.integration_id, pinned_app]),
	}
}

# METADATA
# title: Required checks must pass against the current base
# custom:
#   code: ERR_RULESET_NOT_STRICT
deny contains denial if {
	state.found
	not state.strict
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "strict_required_status_checks_policy is off",
	}
}

# METADATA
# title: Nothing bypasses the ruleset
# custom:
#   code: ERR_RULESET_BYPASS_PRESENT
deny contains denial if {
	state.bypass_actor_count > 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v bypass actor(s) can merge without the gate", [state.bypass_actor_count]),
	}
}

# METADATA
# title: The bypass list must be observable
# custom:
#   code: ERR_RULESET_BYPASS_UNOBSERVED
deny contains denial if {
	state.found
	is_null(state.bypass_actor_count)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "the bypass actor count could not be read, so no bypass cannot be shown",
	}
}

# METADATA
# title: Merges keep their topology
# custom:
#   code: ERR_RULESET_MERGE_METHODS
deny contains denial if {
	state.found
	state.merge_methods != ["merge"]
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("merge methods are %v, not merge commits only", [state.merge_methods]),
	}
}

# METADATA
# title: The pinned app is the one that produces the gate
# custom:
#   code: ERR_RULESET_PRODUCER_MISMATCH
deny contains denial if {
	not is_null(state.producer_app_id)
	state.producer_app_id != pinned_app
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("quality gate is produced by app %v, not %v", [state.producer_app_id, pinned_app]),
	}
}
