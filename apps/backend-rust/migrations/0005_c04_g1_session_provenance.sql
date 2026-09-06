-- C04-G1 / ADR-0011 G2 (integration review follow-up): durable issuance
-- provenance for sessions. G2's bearer-session-v1 device enrollment is
-- authorized only by "a valid, device-unbound, freshly OPAQUE-issued
-- session." Before this migration, "freshly OPAQUE-issued" was true only
-- as a structural side effect of today's call graph (POST
-- /auth/opaque/login is the only issueSession() call site that leaves
-- device_id unset; /auth/refresh's rotateSession() only ever runs on an
-- already device-bound session, per ADR-0005 §2, so it can never itself
-- produce a bearer-session-v1-eligible row). Recording provenance
-- explicitly makes that invariant a stored, checked fact instead of an
-- inference from other code never changing, so a future issuance path
-- cannot silently become eligible for bearer-session-v1 enrollment.
ALTER TABLE sessions
  ADD COLUMN issued_via varchar(32) NOT NULL DEFAULT 'opaque-login'
    CHECK (issued_via IN ('opaque-login', 'refresh'));
