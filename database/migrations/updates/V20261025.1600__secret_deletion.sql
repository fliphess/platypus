-- Secrets scheduled for deletion keep their metadata so admins can see them
-- and restore them (they can no longer be read until restored).
ALTER TABLE items ADD COLUMN deleted_at timestamptz;
