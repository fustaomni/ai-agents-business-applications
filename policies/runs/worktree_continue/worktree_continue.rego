# METADATA
# title: worktree_continue
# description: A rebase is continued only when one is in progress and no marker remains.
package runs.worktree_continue

import rego.v1

# METADATA
# title: The continue plan is supplied, never assumed
# custom:
#   code: ERR_CONTINUE_INPUT_MISSING
deny contains denial if {
	not input.worktree_continue
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no worktree_continue input: an absent plan would read as nothing to refuse",
	}
}

# METADATA
# title: A rebase is in progress
# custom:
#   code: ERR_CONTINUE_NO_REBASE
deny contains denial if {
	input.worktree_continue.operation != "rebase"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("no rebase is in progress (operation: %s)", [
			input.worktree_continue.operation,
		]),
	}
}

# METADATA
# title: No conflict marker remains
# custom:
#   code: ERR_CONTINUE_MARKERS
deny contains denial if {
	some path in input.worktree_continue.with_markers
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s still holds a conflict marker; resolve it first", [path]),
	}
}
