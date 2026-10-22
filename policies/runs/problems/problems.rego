# METADATA
# title: problems
# description: One registry of stable problem codes, read both ways and against the base (D.177).
package runs.problems

import rego.v1

_registered contains entry.code if some entry in input.problems.registry

_live contains entry.code if {
	some entry in input.problems.registry
	not entry.retired
}

_declared contains code if some code in input.problems.declared

_kept(old) if {
	some now in input.problems.registry
	now.code == old.code
	now.title == old.title
	now.severity == old.severity
}

# METADATA
# title: The problems inventory is supplied, never assumed
# custom:
#   code: ERR_PROBLEMS_INPUT_MISSING
deny contains denial if {
	not input.problems
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no problems input: an absent inventory would read as agreement",
	}
}

# METADATA
# title: The rules' declared codes were read
# custom:
#   code: ERR_PROBLEMS_DECLARATIONS_UNREAD
deny contains denial if {
	count(input.problems.declared) == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no declared code was read from the policies: no rules is not every rule registered",
	}
}

# METADATA
# title: Every declared problem code is registered
# custom:
#   code: ERR_PROBLEMS_UNREGISTERED
deny contains denial if {
	some code in input.problems.declared
	not code in _registered
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v is declared by a rule and missing from contracts/problems.toml", [code]),
	}
}

# METADATA
# title: Every live registered code is still declared
# custom:
#   code: ERR_PROBLEMS_UNDECLARED
deny contains denial if {
	some code in _live
	not code in _declared
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v is registered and no rule declares it; retire it rather than delete it", [code]),
	}
}

# METADATA
# title: Each code is registered once
# custom:
#   code: ERR_PROBLEMS_DUPLICATE
deny contains denial if {
	some code in _registered
	count([entry | some entry in input.problems.registry; entry.code == code]) > 1
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v is registered more than once", [code]),
	}
}

# METADATA
# title: The registry on the base was read
# custom:
#   code: ERR_PROBLEMS_BASE_UNREAD
deny contains denial if {
	input.problems.base == null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "origin/develop was not read, so a repurposed code could pass unseen",
	}
}

# METADATA
# title: A registered code is never repurposed
# custom:
#   code: ERR_PROBLEMS_REPURPOSED
deny contains denial if {
	some old in input.problems.base
	not _kept(old)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v changed its title or severity, or was removed; register a new code", [old.code]),
	}
}

# METADATA
# title: No branch decides on prose
# custom:
#   code: ERR_PROBLEMS_PROSE_DISPATCH
deny contains denial if {
	some found in input.problems.prose
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v:%v branches on the wording of %v; decide on a structured field", [
			found.path,
			found.line,
			found.attribute,
		]),
	}
}
