# SPDX-License-Identifier: Apache-2.0
# Adds a native `self_signed` boolean field to x509.log (subject == issuer, computed at
# capture time), closing a T1573 (Encrypted Channel) detection-design blocker: the SIEM's rule
# engine has no cross-field equality operator anywhere in this fleet's ~200-rule custom
# ruleset, so `certificate.subject == certificate.issuer` cannot be expressed as a SIEM rule
# as long as subject/issuer arrive as two separate string fields with the comparison left
# undone. See human/approved/2026-08-26-0748-j6-rfs-zeek-selfsigned-x509-field.md and
# agents/findings/j63/2026-08-26-attack-coverage-map-ed30.md (§T1573).
#
# Reads subject/issuer straight off the event's own `cert` parameter rather than off
# `f$info$x509$certificate` -- avoids depending on the base x509 script having already run
# its own field-population for this same event.
#
# LIVE-VERIFIED SYNTAX 2026-08-26 (`zeek --parse-only` against the deployed zeek/zeek:lts
# image before this was wired into any compose command): the file-analysis framework types
# `f$info` as the GENERIC `Files::Info`, not `X509::Info` -- the base x509 script
# (base/files/x509/main.zeek) sets `f$info$x509 = X509::Info(...)` in its own `x509_certificate`
# handler (priority=5) and every field access downstream goes through that `x509` sub-field, so
# this handler (default priority, runs after) must too -- `f$info$self_signed` directly is not
# a valid path and fails to parse (confirmed live, first draft of this script).
module SelfSigned;

export {
	redef record X509::Info += {
		## True if this certificate's subject and issuer distinguished names are
		## identical -- i.e. self-signed.
		self_signed: bool &log &default=F;
	};
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	if ( f$info?$x509 )
		f$info$x509$self_signed = (cert$subject == cert$issuer);
	}
