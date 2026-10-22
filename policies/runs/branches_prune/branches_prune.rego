# METADATA
# title: branches_prune
# description: A branch is deleted only once it is proven merged, never protected, never in use.
package runs.branches_prune

import rego.v1

# METADATA
# title: The prune request is supplied, never assumed
# custom:
#   code: ERR_BRANCHES_PRUNE_INPUT_MISSING
deny contains denial if {
	not input.branches_prune
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no branches_prune input: an absent request would read as every deletion allowed",
	}
}

# METADATA
# title: A protected branch is never deleted, whatever its state
# custom:
#   code: ERR_BRANCHES_PRUNE_PROTECTED
deny contains denial if {
	some candidate in input.branches_prune.deletions
	candidate.name in input.branches_prune.protected
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s branch %s is protected", [candidate.where, candidate.name]),
	}
}

# METADATA
# title: A branch a worktree holds is in use, and is never deleted
# custom:
#   code: ERR_BRANCHES_PRUNE_HELD
deny contains denial if {
	some candidate in input.branches_prune.deletions
	candidate.held_by != null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s branch %s is checked out at %s", [
			candidate.where,
			candidate.name,
			candidate.held_by,
		]),
	}
}

# METADATA
# title: Only a branch proven merged into the integration branch is deleted
# custom:
#   code: ERR_BRANCHES_PRUNE_UNMERGED
deny contains denial if {
	some candidate in input.branches_prune.deletions
	candidate.merged == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s branch %s holds commits not in develop", [candidate.where, candidate.name]),
	}
}
