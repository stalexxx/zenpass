-- C04-G1 / ADR-0011 G2: honest device-enrollment mode. Forward-only; 001,
-- 002, and 003 are unchanged. `public_key` was NOT NULL because every
-- device previously had one; the new `bearer-session-v1` branch enrolls
-- without any key material, so existing rows are classified
-- 'legacy-public-key' (their real, unchanged semantics: a stored
-- public_key with no proof-of-possession) and public_key becomes optional
-- only for the new mode.
ALTER TABLE devices ALTER COLUMN public_key DROP NOT NULL;

ALTER TABLE devices
  ADD COLUMN enrollment_mode varchar(32) NOT NULL DEFAULT 'legacy-public-key'
    CHECK (enrollment_mode IN ('legacy-public-key', 'bearer-session-v1'));

ALTER TABLE devices
  ADD CONSTRAINT devices_public_key_required_unless_bearer_session
    CHECK (enrollment_mode = 'bearer-session-v1' OR public_key IS NOT NULL);
