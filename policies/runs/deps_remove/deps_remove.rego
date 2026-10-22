# METADATA
# title: deps_remove
# description: A dependency leaves the lock with only what it alone required, or nothing changes.
package runs.deps_remove

import rego.v1

# METADATA
# title: The removal request is supplied, never assumed
# custom:
#   code: ERR_DEPS_REMOVE_INPUT_MISSING
deny contains denial if {
	not input.deps_remove
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no deps_remove input: an absent request would read as any removal allowed",
	}
}

# METADATA
# title: Only a package the project declares is removed
# custom:
#   code: ERR_DEPS_REMOVE_UNDECLARED
deny contains denial if {
	input.deps_remove.declared_before == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is not a dependency of this project", [input.deps_remove.package]),
	}
}

# METADATA
# title: The removed package is no longer declared
# custom:
#   code: ERR_DEPS_REMOVE_NOT_REMOVED
deny contains denial if {
	input.deps_remove.declared_after == true
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is still declared after uv remove", [input.deps_remove.package]),
	}
}

# METADATA
# title: The lock matches pyproject.toml
# custom:
#   code: ERR_DEPS_REMOVE_LOCK_STALE
deny contains denial if {
	input.deps_remove.lock_current == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "uv lock --check failed after the removal",
	}
}

# METADATA
# title: No remaining package changes version
# custom:
#   code: ERR_DEPS_REMOVE_CHANGED
deny contains denial if {
	some name in input.deps_remove.changed
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s changed version: removing never upgrades anything", [name]),
	}
}

# METADATA
# title: Only the package and what it alone required leave the lock
# custom:
#   code: ERR_DEPS_REMOVE_BEYOND
deny contains denial if {
	some name in input.deps_remove.removed
	not name in input.deps_remove.exclusive
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s left the lock, but another package still requires it", [name]),
	}
}
