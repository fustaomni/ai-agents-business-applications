# METADATA
# title: source_outline
# description: A file is outlined only inside the repository, existing, Python, parsed, bounded.
package runs.source_outline

import rego.v1

# METADATA
# title: The outline evidence is supplied, never assumed
# custom:
#   code: ERR_OUTLINE_INPUT_MISSING
deny contains denial if {
	not input.source_outline
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no source_outline input: an absent request would read as one allowed",
	}
}

# METADATA
# title: The file lies inside the repository
# custom:
#   code: ERR_OUTLINE_OUTSIDE_REPOSITORY
deny contains denial if {
	evidence := input.source_outline
	not evidence.inside_repository
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is outside the repository and is never read", [evidence.path]),
	}
}

# METADATA
# title: The file exists
# custom:
#   code: ERR_OUTLINE_NOT_FOUND
deny contains denial if {
	evidence := input.source_outline
	evidence.inside_repository
	not evidence.exists
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s does not exist", [evidence.path]),
	}
}

# METADATA
# title: The file is Python
# custom:
#   code: ERR_OUTLINE_NOT_PYTHON
deny contains denial if {
	evidence := input.source_outline
	evidence.exists
	not evidence.is_python
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is not a Python file", [evidence.path]),
	}
}

# METADATA
# title: The file parses
# custom:
#   code: ERR_OUTLINE_UNPARSEABLE
deny contains denial if {
	evidence := input.source_outline
	evidence.exists
	evidence.is_python
	not evidence.parsed
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s does not parse as Python", [evidence.path]),
	}
}

# METADATA
# title: The outline stays within its bound
# custom:
#   code: ERR_OUTLINE_TOO_LARGE
deny contains denial if {
	evidence := input.source_outline
	evidence.definitions > evidence.limit
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s holds %d definitions, past the limit of %d", [
			evidence.path,
			evidence.definitions,
			evidence.limit,
		]),
	}
}
