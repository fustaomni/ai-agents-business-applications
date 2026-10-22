# METADATA
# title: source_apply
# description: A declarative spec is applied only when every operation is allowed, or not at all.
package runs.source_apply

import rego.v1

# METADATA
# title: The apply request is supplied, never assumed
# custom:
#   code: ERR_SOURCE_APPLY_INPUT_MISSING
deny contains denial if {
	not input.source_apply
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no source_apply input: an absent request would read as every edit allowed",
	}
}

# METADATA
# title: Every path is inside the repository and outside .git
# custom:
#   code: ERR_SOURCE_APPLY_PATH_OUTSIDE
deny contains denial if {
	some operation in input.source_apply.operations
	not operation.inside
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: outside the repository, or under .git", [operation.path]),
	}
}

# METADATA
# title: A created file is new
# custom:
#   code: ERR_SOURCE_APPLY_CREATE_EXISTS
deny contains denial if {
	some operation in input.source_apply.operations
	operation.op == "create"
	operation.exists_before
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: already exists, so create would overwrite it", [operation.path]),
	}
}

# METADATA
# title: A replaced file exists
# custom:
#   code: ERR_SOURCE_APPLY_REPLACE_MISSING
deny contains denial if {
	some operation in input.source_apply.operations
	operation.op == "replace"
	not operation.exists_before
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: does not exist, so nothing can be replaced", [operation.path]),
	}
}

# METADATA
# title: Every anchor is found exactly as often as expected
# custom:
#   code: ERR_SOURCE_APPLY_ANCHOR_COUNT
deny contains denial if {
	some operation in input.source_apply.operations
	operation.op == "replace"
	operation.exists_before
	operation.anchor_count != operation.expected_count
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: anchor found %d time(s), expected %d", [
			operation.path,
			operation.anchor_count,
			operation.expected_count,
		]),
	}
}

# METADATA
# title: Every Python file the spec leaves behind parses
# custom:
#   code: ERR_SOURCE_APPLY_PYTHON_UNPARSEABLE
deny contains denial if {
	some file in input.source_apply.files
	file.python_parses == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: would not parse as Python", [file.path]),
	}
}

# METADATA
# title: Every TOML file the spec leaves behind parses
# custom:
#   code: ERR_SOURCE_APPLY_TOML_UNPARSEABLE
deny contains denial if {
	some file in input.source_apply.files
	file.toml_parses == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: would not parse as TOML", [file.path]),
	}
}

# METADATA
# title: No line the spec writes into Python passes the line limit
# custom:
#   code: ERR_SOURCE_APPLY_LINE_TOO_LONG
deny contains denial if {
	some operation in input.source_apply.operations
	operation.longest_written_python_line > input.source_apply.line_limit
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: writes a %d-column line; the limit is %d", [
			operation.path,
			operation.longest_written_python_line,
			input.source_apply.line_limit,
		]),
	}
}

# METADATA
# title: A deleted file exists
# custom:
#   code: ERR_SOURCE_APPLY_DELETE_MISSING
deny contains denial if {
	some operation in input.source_apply.operations
	operation.op == "delete"
	not operation.exists_before
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: does not exist, so nothing can be deleted", [operation.path]),
	}
}

# METADATA
# title: Only a file git tracks is deleted, so history can restore it
# custom:
#   code: ERR_SOURCE_APPLY_DELETE_UNTRACKED
deny contains denial if {
	some operation in input.source_apply.operations
	operation.op == "delete"
	operation.exists_before
	not operation.tracked
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: git does not track it, so deleting it could not be undone", [operation.path]),
	}
}
