-- Profile details users fill in themselves, so people are recognised by name
-- rather than by email address.
ALTER TABLE users ADD COLUMN display_name text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN department text NOT NULL DEFAULT '';
