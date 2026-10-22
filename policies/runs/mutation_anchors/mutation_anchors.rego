# METADATA
# title: mutation_anchors
# description: Every mutation spec resolves, each anchor found exactly once (D.222).
package runs.mutation_anchors

import rego.v1

# METADATA
# title: The anchor inventory is supplied, never assumed
# custom:
#   code: ERR_MUTATION_ANCHORS_INPUT_MISSING
deny contains denial if {
	not input.mutation_anchors
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no anchor inventory: an absent one would read as every spec resolving",
	}
}

# METADATA
# title: The gate read at least one spec
# custom:
#   code: ERR_MUTATION_ANCHORS_NOTHING_SCANNED
deny contains denial if {
	input.mutation_anchors.specs_scanned == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no mutation spec was read: an empty inventory proves nothing",
	}
}

# METADATA
# title: Every spec reads as a mutation spec
# custom:
#   code: ERR_MUTATION_ANCHORS_UNREADABLE
deny contains denial if {
	some unread in input.mutation_anchors.unreadable
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v cannot be read as a mutation spec: %v", [unread.spec, unread.reason]),
	}
}

# METADATA
# title: Every anchor is still in its file
# custom:
#   code: ERR_MUTATION_ANCHORS_STALE
deny contains denial if {
	some anchor in input.mutation_anchors.anchors
	anchor.count == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v: mutant %v no longer finds its anchor in %v", [anchor.spec, anchor.mutant, anchor.file]),
	}
}

# METADATA
# title: No anchor is ambiguous
# custom:
#   code: ERR_MUTATION_ANCHORS_AMBIGUOUS
deny contains denial if {
	some anchor in input.mutation_anchors.anchors
	anchor.count > 1
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf(
			"%v: mutant %v finds its anchor %v times in %v",
			[anchor.spec, anchor.mutant, anchor.count, anchor.file],
		),
	}
}
