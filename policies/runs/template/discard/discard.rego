# policies/runs/template/discard/discard.rego

# METADATA
# title: Template discard policy
# description: Only an untouched, unpublished generated project is removed.
# entrypoint: true
package runs.template.discard

# An ACTION policy (D.63): template:discard builds the request and asks in the same call,
# so every negated rule first requires it, and the repository gate, which supplies none,
# is silent. Removal is irreversible, so every fact it rests on is refused here.

import rego.v1

# METADATA
# title: The destination was generated
# description: Without .copier-answers.yml it is not a generated project.
# custom:
#   code: ERR_DISCARD_NOT_GENERATED
deny contains denial if {
	input.template_discard
	not input.template_discard.answers_present
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s holds no .copier-answers.yml", [input.template_discard.resolved]),
	}
}

# METADATA
# title: The destination is not a symlink
# description: Removing through a link would remove what it points at.
# custom:
#   code: ERR_DISCARD_SYMLINK
deny contains denial if {
	input.template_discard.is_symlink
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is a symlink", [input.template_discard.destination]),
	}
}

# METADATA
# title: The destination is not published
# description: A project with a remote may be known elsewhere.
# custom:
#   code: ERR_DISCARD_PUBLISHED
deny contains denial if {
	input.template_discard.has_remote
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s has a remote", [input.template_discard.resolved]),
	}
}

# METADATA
# title: The destination holds only its birth
# description: template:init's commit, then template:identity's; anything more is somebody's work.
# custom:
#   code: ERR_DISCARD_AUTHORED
deny contains denial if {
	input.template_discard
	not birth
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s holds more than its birth", [input.template_discard.resolved]),
	}
}

# METADATA
# title: The destination is clean
# description: Uncommitted changes are work nothing else records.
# custom:
#   code: ERR_DISCARD_DIRTY
deny contains denial if {
	input.template_discard
	not input.template_discard.clean
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s has uncommitted changes", [input.template_discard.resolved]),
	}
}

# METADATA
# title: The destination is not this repository, home or a root
# description: The source, anything holding it, the home directory and a root are never removed.
# custom:
#   code: ERR_DISCARD_PROTECTED
deny contains denial if {
	input.template_discard.protected
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is protected", [input.template_discard.resolved]),
	}
}

# METADATA
# title: The removal resists symlink attacks
# description: rmtree is attack-resistant only where avoids_symlink_attacks is true.
# custom:
#   code: ERR_DISCARD_UNSAFE
deny contains denial if {
	input.template_discard
	not input.template_discard.safe_removal
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: rmtree here does not avoid symlink attacks", [input.template_discard.resolved]),
	}
}

# METADATA
# title: The template:discard request is present
# description: Without it every rule above judges nothing, and an empty judgement reads as a pass.
# custom:
#   code: ERR_DISCARD_INPUT_MISSING
deny contains denial if {
	not input.template_discard
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no template_discard was supplied, so no rule judged the request",
	}
}

# THE BIRTH (D.63, D.264): the generated commit alone, or it and the identity commit as the
# request names them from the tasks that write them; this policy restates no subject.
birth if input.template_discard.commits == 1

birth if {
	input.template_discard.commits == 2
	input.template_discard.subjects == input.template_discard.birth_subjects
}
