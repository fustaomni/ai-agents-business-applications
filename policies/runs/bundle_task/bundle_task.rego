# METADATA
# title: bundle_task
# description: A bundle deploy or run reaches the workspace only when it can succeed as judged.
package runs.bundle_task

import rego.v1

# METADATA
# title: The bundle request is supplied, never assumed
# custom:
#   code: ERR_BUNDLE_TASK_INPUT_MISSING
deny contains denial if {
	not input.bundle_task
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no bundle_task input: an absent request would read as any deploy allowed",
	}
}

# METADATA
# title: The target is one the bundle declares
# custom:
#   code: ERR_BUNDLE_TASK_TARGET_UNDECLARED
deny contains denial if {
	input.bundle_task.target_declared == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("target %s is not declared in databricks.yml", [input.bundle_task.target]),
	}
}

# METADATA
# title: Every required bundle variable has a value, and its remedy is named
# custom:
#   code: ERR_BUNDLE_TASK_VARIABLE_UNSET
deny contains denial if {
	some name in input.bundle_task.unset
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf(
			"bundle variable %s has no value: set BUNDLE_VAR_%s under [env] in ~/.config/mise/config.toml",
			[name, name],
		),
	}
}

# METADATA
# title: A deploy validates strictly first, on the same target
# custom:
#   code: ERR_BUNDLE_TASK_UNVALIDATED
deny contains denial if {
	input.bundle_task.action == "deploy"
	not _validated_first
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("a deploy to %s must first run validate --strict on that target", [input.bundle_task.target]),
	}
}

_validated_first if {
	first := input.bundle_task.commands[0]
	first[2] == "validate"
	"--strict" in first
	every command in input.bundle_task.commands {
		_target(command) == input.bundle_task.target
	}
}

_target(command) := command[i + 1] if {
	some i, word in command
	word == "-t"
}
