# METADATA
# title: branches_retire
# description: An unmerged branch is retired only by name, for a known step, archived first.
package runs.branches_retire

import rego.v1

# METADATA
# title: The retire request is supplied, never assumed
# custom:
#   code: ERR_BRANCHES_RETIRE_INPUT_MISSING
deny contains denial if {
	not input.branches_retire
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no branches_retire input: an absent request would read as retirement allowed",
	}
}

# METADATA
# title: A protected branch is never retired
# custom:
#   code: ERR_BRANCHES_RETIRE_PROTECTED
deny contains denial if {
	input.branches_retire.branch in input.branches_retire.protected
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is protected", [input.branches_retire.branch]),
	}
}

# METADATA
# title: A branch a worktree holds is in use, and is never retired
# custom:
#   code: ERR_BRANCHES_RETIRE_HELD
deny contains denial if {
	input.branches_retire.held_by != null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is checked out at %s; remove that worktree first", [
			input.branches_retire.branch,
			input.branches_retire.held_by,
		]),
	}
}

# METADATA
# title: A branch is retired only for a step the plan declares
# custom:
#   code: ERR_BRANCHES_RETIRE_STEP_UNKNOWN
deny contains denial if {
	input.branches_retire.step_known == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is not a step the plan declares", [input.branches_retire.step]),
	}
}

# METADATA
# title: An existing archive is never overwritten
# custom:
#   code: ERR_BRANCHES_RETIRE_ARCHIVED
deny contains denial if {
	input.branches_retire.archived == true
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("archive/%s already exists", [input.branches_retire.branch]),
	}
}
