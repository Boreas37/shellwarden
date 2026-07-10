-- Bulk jobs can run a multi-line script (piped to bash -s) instead of a command.
ALTER TABLE bulk_jobs ADD COLUMN IF NOT EXISTS is_script BOOLEAN NOT NULL DEFAULT FALSE;
