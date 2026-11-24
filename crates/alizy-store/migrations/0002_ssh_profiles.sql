-- SSH-tunnel profiles. `ssh_public` holds only the non-secret SshPublic JSON;
-- the password lives in the OS secret store under "ssh:<id>", never here.
-- SSH rows keep a placeholder WireGuard projection in `public_config`.
ALTER TABLE profiles ADD COLUMN kind TEXT NOT NULL DEFAULT 'wireguard';
ALTER TABLE profiles ADD COLUMN ssh_public TEXT;
ALTER TABLE profiles ADD COLUMN password_needed INTEGER NOT NULL DEFAULT 0;
