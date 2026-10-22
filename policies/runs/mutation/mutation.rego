# METADATA
# title: mutation
# description: Every named killer kills its mutant, judged one killer at a time.
package runs.mutation

import rego.v1

# A FAILED RUN'S OWN WORDS (D.106): its tail, when it has one. object.get keeps an input without
# a tail producing its message, rather than leaving a rule undefined and its denial unraised.
_said(run) := sprintf(": %s", [concat(" | ", object.get(run, "tail", []))]) if count(object.get(run, "tail", [])) > 0

_said(run) := "" if count(object.get(run, "tail", [])) == 0

_judged(code) if code in {0, 1, 2}

# METADATA
# title: The mutation evidence is supplied, never assumed
# custom:
#   code: ERR_MUTATION_INPUT_MISSING
deny contains denial if {
	not input.mutation
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no mutation input: an absent run would read as every mutant killed",
	}
}

# METADATA
# title: The tree under test could be listed
# custom:
#   code: ERR_MUTATION_TREE_UNLISTED
deny contains denial if {
	input.mutation.tree_listed == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "git could not list the tree, so nothing was copied or run",
	}
}

# METADATA
# title: Every killer passes before any mutant is applied
# custom:
#   code: ERR_MUTATION_BASELINE_FAILED
deny contains denial if {
	some run in input.mutation.baseline
	run.exit_code != 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s fails unmutated (exit %d)%s", [run.test, run.exit_code, _said(run)]),
	}
}

# METADATA
# title: Every mutant's anchor is found exactly once
# custom:
#   code: ERR_MUTATION_ANCHOR_NOT_ONCE
deny contains denial if {
	some mutant in input.mutation.mutants
	not mutant.anchor_found_once
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: its anchor is not found once in %s", [mutant.id, mutant.file]),
	}
}

# METADATA
# title: Every named killer kills its mutant
# custom:
#   code: ERR_MUTATION_SURVIVED_ITS_KILLER
deny contains denial if {
	some mutant in input.mutation.mutants
	some run in mutant.runs
	run.exit_code == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s survived %s", [mutant.id, run.test]),
	}
}

# METADATA
# title: Every killer's result could be judged
# custom:
#   code: ERR_MUTATION_KILLER_UNJUDGED
deny contains denial if {
	some mutant in input.mutation.mutants
	some run in mutant.runs
	not _judged(run.exit_code)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: %s could not be judged (exit %d)%s", [
			mutant.id,
			run.test,
			run.exit_code,
			_said(run),
		]),
	}
}

# METADATA
# title: The tree under test is never mutated in place
# custom:
#   code: ERR_MUTATION_TREE_TOUCHED
deny contains denial if {
	input.mutation.tree_untouched == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "the original tree changed while mutants ran",
	}
}
