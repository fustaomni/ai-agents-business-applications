# METADATA
# title: layers
# description: Every module implements all five layers, or a planned step owns its fix.
package layers

import rego.v1

_owned(module) if {
	module.owner != null
	module.owner_planned
	not module.owner_committed
}

# INHERITED BY A GENERATED PROJECT: owned by the template, fixed by its update.
_owned(module) if {
	module.owner != null
	module.owner_upstream
}

_on_spine(module) if {
	module.imports_spine
	module.returns_enforce
}

_failing(module) if {
	module.entry_point
	not _on_spine(module)
}

_failing(module) if count(module.exits) > 0

# METADATA
# title: An entry point evaluates, decides and enforces through the spine
# custom:
#   code: ERR_LAYERS_ENTRY_NOT_ON_SPINE
deny contains denial if {
	some module in input.layer_audit.modules
	module.entry_point
	not _on_spine(module)
	not _owned(module)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s exits without spine.evaluate, decide and enforce", [module.path]),
	}
}

# METADATA
# title: An entry point exits only from its __main__ guard
# custom:
#   code: ERR_LAYERS_EXIT_NOT_FROM_DECISION
deny contains denial if {
	some module in input.layer_audit.modules
	module.entry_point
	count(module.exits) > 0
	not _owned(module)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s exits outside its guard at lines %v", [module.path, module.exits]),
	}
}

# METADATA
# title: A library never exits the process
# custom:
#   code: ERR_LAYERS_LIBRARY_EXITS
deny contains denial if {
	some module in input.layer_audit.modules
	not module.entry_point
	count(module.exits) > 0
	not _owned(module)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("library %s exits the process at lines %v", [module.path, module.exits]),
	}
}

# METADATA
# title: A committed step cannot still own a failing module
# custom:
#   code: ERR_LAYERS_OWNER_ALREADY_DONE
deny contains denial if {
	some module in input.layer_audit.modules
	module.owner != null
	module.owner_committed
	_failing(module)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s still fails though %s is committed", [module.path, module.owner]),
	}
}

# METADATA
# title: The audit's evidence is supplied, never assumed
# custom:
#   code: ERR_LAYERS_INPUT_MISSING
deny contains denial if {
	not input.layer_audit
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no layer_audit input: an absent audit would read as every module passing",
	}
}
