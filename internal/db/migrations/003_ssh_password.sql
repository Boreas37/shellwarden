-- Add optional password-based SSH auth alongside key-based auth.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_password TEXT;
