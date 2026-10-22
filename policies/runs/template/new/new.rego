# policies/runs/template/new/new.rego

# METADATA
# title: Template generation policy
# description: A project comes from the declared repository, at a full sha, into a new place.
# entrypoint: true
package runs.template.new

# An ACTION policy: template:new builds the request and asks in the same call, so every
# rule first requires the request, and the repository gate, which supplies none, judges
# nothing here (D.54). deps.add is the same shape.

import rego.v1

# METADATA
# title: The ref is a full commit sha
# description: HEAD, a branch, a tag or a short sha lets Copier choose; a full sha pins.
# custom:
#   code: ERR_TEMPLATE_UNPINNED
deny contains denial if {
	input.template_request
	not regex.match(`^[0-9a-f]{40}$`, input.template_request.ref)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is not a full commit sha, so Copier would choose the version", [input.template_request.ref]),
	}
}

# METADATA
# title: The destination is new
# description: Generating over existing files would mix two projects in one directory.
# custom:
#   code: ERR_TEMPLATE_DESTINATION_OCCUPIED
deny contains denial if {
	input.template_request.destination_exists
	not input.template_request.destination_empty
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s already holds files", [input.template_request.destination]),
	}
}

# METADATA
# title: The destination is outside the source
# description: A project generated inside its template would be committed into it.
# custom:
#   code: ERR_TEMPLATE_DESTINATION_INSIDE
deny contains denial if {
	input.template_request.inside_source
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is inside the template repository", [input.template_request.destination]),
	}
}

# METADATA
# title: The source is SSH
# description: This machine reaches GitHub over SSH; HTTPS stops at a credential prompt (D.57).
# custom:
#   code: ERR_TEMPLATE_SOURCE_NOT_SSH
deny contains denial if {
	input.template_request
	not startswith(input.template_request.transport, concat("@", ["git", "github.com:"]))
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is not an SSH transport, so the clone would wait for a prompt", [
			input.template_request.transport,
		]),
	}
}

# METADATA
# title: The template:new request is present
# description: Without it every rule above judges nothing, and an empty judgement reads as a pass.
# custom:
#   code: ERR_TEMPLATE_INPUT_MISSING
deny contains denial if {
	not input.template_request
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no template_request was supplied, so no rule judged the request",
	}
}
