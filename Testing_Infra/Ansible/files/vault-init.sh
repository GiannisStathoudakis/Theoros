#!/bin/sh
set -e

CLOUDFLARE_TOKEN="$1"
EMAIL="$2"

# Check if Vault is already exists
if vault status 2>&1 | grep -q "Initialized.*true"; then
    if [ -f /tmp/cluster-keys.json ]; then
        VAULT_ROOT_TOKEN=$(grep '"root_token":' /tmp/cluster-keys.json | awk -F'"' '{print $4}')
        vault login "$VAULT_ROOT_TOKEN"
    fi
else
    vault operator init -key-shares=5 -key-threshold=3 -format=json > /tmp/cluster-keys.json

    VAULT_ROOT_TOKEN=$(grep '"root_token":' /tmp/cluster-keys.json | awk -F'"' '{print $4}')
    UNSEAL_KEY_1=$(grep '"unseal_keys_b64":' -A 5 /tmp/cluster-keys.json | awk -F'"' 'NR==2 {print $2}')
    UNSEAL_KEY_2=$(grep '"unseal_keys_b64":' -A 5 /tmp/cluster-keys.json | awk -F'"' 'NR==3 {print $2}')
    UNSEAL_KEY_3=$(grep '"unseal_keys_b64":' -A 5 /tmp/cluster-keys.json | awk -F'"' 'NR==4 {print $2}')

    vault operator unseal "$UNSEAL_KEY_1"
    vault operator unseal "$UNSEAL_KEY_2"
    vault operator unseal "$UNSEAL_KEY_3"

    vault login "$VAULT_ROOT_TOKEN"
fi

# Enable KV Version 2 Engine
vault secrets enable -path=secret kv-v2 || true

# Enable Kubernetes Authentication
vault auth enable kubernetes || true
vault write auth/kubernetes/config kubernetes_host="https://kubernetes.default.svc:443" || true

# Configure ESO Policies
echo "Configuring ESO Policies..."
echo 'path "secret/data/*" { capabilities = ["read"] }' > /tmp/eso-policy.hcl
echo 'path "secret/metadata/*" { capabilities = ["read", "list"] }' >> /tmp/eso-policy.hcl

vault policy write eso-policy /tmp/eso-policy.hcl

vault write auth/kubernetes/role/eso-role \
    bound_service_account_names=external-secrets \
    bound_service_account_namespaces=external-secrets \
    policies=eso-policy \
    ttl=24h

vault kv put secret/cloudflare api-token="$CLOUDFLARE_TOKEN"