-- How the user wants times shown: 'utc' (default) or 'local' (their
-- browser's time zone). Purely a display preference.
ALTER TABLE users ADD COLUMN timezone text NOT NULL DEFAULT 'utc';
