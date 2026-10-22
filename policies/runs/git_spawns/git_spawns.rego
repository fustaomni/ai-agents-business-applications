# METADATA
# title: Git spawn policy
# description: Every git subprocess outside gitenv runs in its scrubbed environment (D.39).
package runs.git_spawns

import rego.v1

inventory := input.git_spawns

# METADATA
# title: The git spawns must be observed
# custom:
#   code: ERR_GIT_SPAWNS_INPUT_MISSING
deny contains denial if {
	not inventory.contract
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "the git spawns were not observed",
	}
}

# METADATA
# title: Something must have been scanned
# custom:
#   code: ERR_GIT_SPAWNS_NOTHING_SCANNED
deny contains denial if {
	inventory.contract
	inventory.files_scanned == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no script was scanned, so no spawn could be judged",
	}
}

# METADATA
# title: A subprocess running git uses gitenv's scrubbed environment
# custom:
#   code: ERR_GIT_SPAWN_UNSCRUBBED
deny contains denial if {
	some spawn in inventory.spawns
	spawn.kind == "subprocess"
	not spawn.env_from_gitenv
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s:%d runs git without gitenv's scrubbed environment", [spawn.path, spawn.line]),
	}
}

# METADATA
# title: A generic runner is never handed git
# custom:
#   code: ERR_GIT_SPAWN_HELPER
deny contains denial if {
	some spawn in inventory.spawns
	spawn.kind == "helper"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s:%d hands git to a generic runner; use gitenv.git", [spawn.path, spawn.line]),
	}
}
