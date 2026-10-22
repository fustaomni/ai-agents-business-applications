# METADATA
# title: run_request
# description: The gateway starts only a task mise.toml declares.
package runs.run_request

import rego.v1

# METADATA
# title: The run request is supplied, never assumed
# custom:
#   code: ERR_RUN_INPUT_MISSING
deny contains denial if {
	not input.run_request
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no run_request input: an absent request would read as a task to start",
	}
}

# METADATA
# title: Only a declared task is started
# custom:
#   code: ERR_RUN_TASK_UNDECLARED
deny contains denial if {
	request := input.run_request
	not request.declared
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is not declared in mise.toml: the gateway starts only declared tasks", [
			request.task,
		]),
	}
}

# METADATA
# title: A mutating task never runs twice at once in one worktree
# custom:
#   code: ERR_RUN_DUPLICATE_EXECUTION
deny contains denial if {
	request := input.run_request
	request.mutating
	not request.exclusive
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is already running in this worktree: it never runs twice at once", [
			request.task,
		]),
	}
}
