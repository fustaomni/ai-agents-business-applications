# METADATA
# title: back_merge
# description: main is merged into a branch from develop only off the protected branches, clean.
package runs.back_merge

import rego.v1

# METADATA
# title: The back-merge request is supplied, never assumed
# custom:
#   code: ERR_BACK_MERGE_INPUT_MISSING
deny contains denial if {
	not input.back_merge
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no back_merge input: an absent request would read as a merge allowed",
	}
}

# METADATA
# title: develop and main change only through a pull request, never by a back-merge
# custom:
#   code: ERR_BACK_MERGE_PROTECTED
deny contains denial if {
	input.back_merge.branch in input.back_merge.protected
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is protected: back-merge in a branch cut from develop", [input.back_merge.branch]),
	}
}

# METADATA
# title: A back-merge starts from a clean working tree
# custom:
#   code: ERR_BACK_MERGE_DIRTY
deny contains denial if {
	input.back_merge.clean == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s has uncommitted changes: commit or restore them first", [input.back_merge.branch]),
	}
}
