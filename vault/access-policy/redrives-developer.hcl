path "secret/data/redrives/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/redrives" {
  capabilities = ["list"]
}

path "secret/metadata/redrives/*" {
  capabilities = ["read", "list"]
}
