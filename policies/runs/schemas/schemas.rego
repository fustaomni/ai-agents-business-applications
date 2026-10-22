# METADATA
# title: schemas
# description: Every versioned contract's schema is committed; a break needs a new version.
package runs.schemas

import rego.v1

# A READER NEVER BREAKS ON THESE: a property added as optional, a requirement relaxed, a type
# widened, an enum value added, an annotation reworded (D.147).
compatible := {
	"annotation_changed",
	"enum_value_added",
	"optional_property_added",
	"property_became_optional",
	"type_widened",
}

# A change a reader can trip on, under identifiers that did not change.
breaking(entry) if {
	entry.ids == entry.snapshot_ids
	some change in entry.changes
	not change.kind in compatible
}

# METADATA
# title: The schema inventory is supplied, never assumed
# custom:
#   code: ERR_SCHEMAS_INPUT_MISSING
deny contains denial if {
	not input.schemas
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no schemas input: an absent inventory would read as a clean one",
	}
}

# METADATA
# title: An audit that found no versioned contract proves nothing
# custom:
#   code: ERR_SCHEMAS_NOTHING_SCANNED
deny contains denial if {
	count(input.schemas.contracts) == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no versioned contract was found: the audit judged nothing",
	}
}

# METADATA
# title: Every versioned contract has a committed schema
# custom:
#   code: ERR_SCHEMAS_UNSNAPSHOTTED
deny contains denial if {
	some entry in input.schemas.contracts
	is_null(entry.snapshot_digest)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s has no committed schema: run mise run run schemas:snapshot", [entry.entry]),
	}
}

# METADATA
# title: A changed schema is committed deliberately
# custom:
#   code: ERR_SCHEMAS_STALE
deny contains denial if {
	some entry in input.schemas.contracts
	not is_null(entry.snapshot_digest)
	entry.digest != entry.snapshot_digest
	not breaking(entry)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s changed since its snapshot: run mise run run schemas:snapshot", [entry.entry]),
	}
}

# METADATA
# title: A change that can break a reader needs a new version
# custom:
#   code: ERR_SCHEMAS_BREAKING
deny contains denial if {
	some entry in input.schemas.contracts
	breaking(entry)
	kinds := [change.kind | some change in entry.changes; not change.kind in compatible]
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: %v under the same identifiers; give it a new version", [entry.entry, kinds]),
	}
}

# METADATA
# title: A snapshot belongs to a versioned contract
# custom:
#   code: ERR_SCHEMAS_ORPHANED
deny contains denial if {
	some orphan in input.schemas.orphans
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s.json has no versioned contract: run mise run run schemas:snapshot", [orphan]),
	}
}
