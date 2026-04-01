# Vault policy for Akeyless USC token refresh with secret_id self-rotation
#
# Before applying, replace:
#   <MOUNT>  with your AppRole mount path  (default: approle)
#   <ROLE>   with your AppRole role name   (matches VAULT_APPROLE_ROLE_NAME in .env)
#
# Apply:
#   vault policy write usc-access policies/usc-access.hcl

# --- Secret access (what the Akeyless USC reads) ---
path "secret/data/*"          { capabilities = ["create", "read", "update", "delete", "list"] }
path "secret/metadata/*"      { capabilities = ["read", "list", "delete"] }
path "secret/delete/*"        { capabilities = ["update"] }
path "secret/undelete/*"      { capabilities = ["update"] }
path "secret/destroy/*"       { capabilities = ["update"] }

# --- System (USC needs this to detect KV v1 vs v2) ---
path "sys/mounts"             { capabilities = ["read"] }
path "sys/mounts/*"           { capabilities = ["read"] }

# --- Token introspection ---
path "auth/token/lookup-self" { capabilities = ["read"] }

# --- Secret ID self-rotation ---
path "auth/<MOUNT>/role/<ROLE>/secret-id"         { capabilities = ["update"] }
path "auth/<MOUNT>/role/<ROLE>/secret-id/lookup"   { capabilities = ["update"] }
path "auth/<MOUNT>/role/<ROLE>/secret-id/destroy"  { capabilities = ["update"] }
