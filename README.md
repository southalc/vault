# vault_secrets

## Table of Contents

1. [Description](#description)
1. [Vault Setup](#setup)
1. [Usage](#usage)
1. [Reference](#reference)
1. [Limitations](#limitations)
1. [Development](#development)

## Description

This module provides functions to integrate Hashicorp Vault with Puppet and uses the main module class to enable
issuing and renewing host certificates from a Vault PKI secrets engine.  The module has no dependencies other than
'puppetlabs-stdlib' and requires no extra ruby gems on the Puppet server or agents.  If you only want to use the
functions without issuing host certificates from Vault, add the module to an environment without assigning it to
any nodes.

The custom hiera backend `vault_hiera_hash` enables the puppet server to use a Vault key/value secrets engine as
a hiera data_hash.  This allows storing multiple key/value pairs on a given Vault path, then using it from hiera
much like local YAML files.  The function supports both v1 and v2 of the Vault key/value secrets engine and is
useful to easily separate secrets from other version controlled hiera data.

The `vault_hash` and `vault_key` functions also support Vault key/value secrets engines version 1 and 2, and can
be used in manifests to get secrets from Vault.  With Puppet agents 6 and later you can also use
[deferred functions](https://puppet.com/docs/puppet/latest/deferred_functions.html) to enable clients to get
secrets directly from Vault without passing them through the Puppet server.

## Setup

Obviously you need to have a working Hashicorp Vault deployment first.  Complete the following steps on the Vault server:

1. Enable a kv secrets engine on path 'puppet/'.  This example is for version 1 of the k/v engine:
```
vault secrets enable -path=puppet -description="Puppet data" -version=1 kv
```

2. Use the Vault UI or command line to create a secret under the 'puppet/' path.  This example will use the name "common"
as the secret name for storing key/value secrets common to all nodes.

3. Configure Vault to enable authentication with certificates issued by the Puppet certificate authority.  From a Puppet
node you can reference the Puppet CA certificate from: '/etc/puppetlabs/puppet/ssl/certs/ca.pem'.  When using PKI
authentication, the module functions will authenticate every Vault request independently, so use a low "ttl" value to
keep from building up many active Vault tokens.  Alternatively, you can generate a long-term Vault token for use with
the `vault_hiera_hash` function as a way to reduce overhead during hiera lookups.
```
vault auth enable -path=puppet-pki -description="PKI authentication with Puppet certificates" cert
vault write auth/puppet-pki/certs/puppetCA \
  display_name="Puppet CA" \
  policies=puppet \
  certificate=@/etc/puppetlabs/puppet/ssl/certs/ca.pem \
  ttl=60
```

If you don't want to use deferred functions and just want to use Vault with hiera, it's recommended to manually create
a Vault token.  This avoids the overhead of certificate authentication with every hiera lookup.  Set up a Vault policy
for Puppet first per the example in setup step #5, then create the Vault token:
```
vault token create -display-name="Puppet hiera lookups" -orphan -policy=puppet
```

4. Optionally enable a PKI secrets engine on Vault to serve as a certificate authority and get dynamic provisioning of X.509
certificates.
```
vault secrets enable -description="PKI service" -path=pki pki
```
With the 'pki' secrets engine enabled, create a certificate authority for Vault.  There are several options to set
this up, depending on your security requirements.  Choose one of the following methods:

Option 1 - Create a new root CA in Vault.  When setting up a root CA, you will likely want to increase the max lifetime of
the certificate first.  It seems Vault doesn't understand logical units for days or years, so we are forced in to using
hours (this example is ~10 years in hours):
```
vault secrets tune -max-lease-ttl=87600h pki
```
With the max lifetime set to a reasonable value for a root CA, generate the new root certificate in Vault, using the
max TTL:
```
vault write pki/root/generate/internal common_name='Vault Root CA'  ttl=87600h
```

Option 2 - From Vault, create a certificate signing request for a subordinate certificate authority.  Submit the CSR to an
external CA for signing, then import the signed certificate into Vault.  First, set the max lifetime of certificates to a
good working value for a subordinate CA.  This example is 5 years, in hours:
```
vault secrets tune -max-lease-ttl=43800h pki
```
Generate the subordinate CSR from Vault, using a common name as you like and using the max TTL we just defined:
```
vault write pki/intermediate/generate/internal common_name="Sub CA" ttl=43800h
```
Capture the CSR from the output of the last command and submit it to the upstream CA for signing.  When you get the
signed certificate back, import the upstream CA certificate into Vault, then import the the signed subordinate CA
certificate:
```
vault write pki/intermediate/set-signed certificate=@signed_certificate.pem
```

Option 3 - Externally from Vault, generate a signed certificate for a subordinate CA.  Create a certificate chain
beginning with the private key of the subordinate CA, the signed subordinate certificate, any intermediate CA
certificates, and finally the root CA certificate.  The private key of the new subordinate CA will need to be in
decrypted form for the certificate chain to be imported into to Vault:
```
vault write pki/config/ca pem_bundle=@subca-chain.pem
```

With the certificate authority established, define the endpoints for issuing certificates and revocation lists.  These
can be modified later if needed:
```
vault write pki/config/urls \
  issuing_certificates="http://vault.example.local:8200/v1/pki/ca" \
  crl_distribution_points="http://vault.example.local:8200/v1/pki/crl"
```

Configure one or more roles for the pki service.  The role is where the certificate attributes can be defined.  Policy
can be used to enable access to different roles as needed:
```
vault write pki/roles/example-local \
  allowed_domains=example.local \
  allow_subdomains=true max_ttl=168h \
  organization=Example \
  ou=Automation \
  country=US \
```

To view all the possible settings that could be defined by the role:
```
vault read  pki/roles/example-local
```

To issue a certificate from the pki service, invoke a write to the role.  We'll be using this Puppet module to
automate this and to automatically renew certificates as they near the expiration date.
```
vault write pki/issue/example-local common_name=myhost.example.local
```

5. Create a policy on Vault to enable access to Puppet data.  This policy example grants read access to everything under the
Vault path "puppet/nodes" and the specific Vault path "puppet/common".  The "pki/issue/example-local" is granted 'update' access
to enable Puppet to obtain PKI certificates from the configured role on the Vault certificate authority.  Applying this policy
to the 'puppet-pki' authentication path will enable any Puppet certificate to authenticate and access these Vault paths.  Review
the Vault documentation for managing access to Vault with policies. Save the policy to a file:
```
path "puppet/nodes/*" {
  capabilities = ["read"]
}
path "puppet/common" {
  capabilities = ["read"]
}
path "pki/issue/example-local" {
  capabilities = ["update"]
}
```
Write the policy to Vault on the 'puppet-pki' authentication path:
```
vault policy write puppet-pki <file>
```

## Usage

Here are some examples of using the module functions to obtain secrets from Vault.  The 'vault_hash' function
returns a hash of all keys/values from a Vault server on a given path, authenticating with the 'puppet-pki'
method:
```
$vault_hash = vault_hash('https://vault.example.com:8200/v1/puppet/common', 'puppet-pki')
notify { 'hash_example' :
  message => $vault_hash,
}
```
The 'vault_key' function returns only the value from the specified Vault URI, path, and key:
```
$vault_value = vault_key('https://vault.example.com:8200/v1/puppet/common', 'puppet-pki', 'secret_key')
notify { 'key_example' :
  message => $vault_value,
}
```
Functions may be deferred so they run from the managed node instead of the Puppet server.  This way the secret
is passed directly from Vault to the client where it is needed:
```
$deferred_hash = Deferred('vault_hash', ['https://vault.example.com:8200/v1/puppet/common', 'puppet-pki'])
notify { 'deferred_example' :
  message => $deferred_hash,
}

$deferred_value = Deferred('vault_key', ['https://vault.example.com:8200/v1/puppet/common', 'puppet-pki', 'secret_key'])
notify { 'deferred_example' :
  message => $deferred_value,
}
```
### Vault as a hiera backend

Configure an environment to use the custom hiera backend by using the 'vault_hiera_hash' function for the data_hash.
This enables the Puppet server to lookup all key/value pairs stored on a Vault secrets path in a single lookup.  You
can also pass an array of 'uris' that may include variable references to be interpolated at runtime.  Note that each uri
results in a separate Vault request and will incur some overhead on the Puppet server.  The 'options' hash requires a
'ca_trust' value, which is the certificate authority chain used to validate the TLS connection to Vault.
```
hierarchy:
  - name: "Secrets from Vault"
    data_hash: vault_hiera_hash
    uri: "https://vault.example.com:8200/v1/puppet/common"   # Secrets common to all nodes
    options:
      timeout: 3
      auth_path: "puppet-pki"
      ca_trust: "/etc/ssl/certs/ca-certificates.crt"
```
Example configuration using Vault for hiera data using multiple search paths and a pre-staged Vault token to avoid
authentication overhead with each lookup.  When using a Vault token, ensure the 'token_file' has read permissions by
the user running the Puppet server process.  Obviously this is a security sensitive file that should be protected from
all other access.
```
hierarchy:
  - name: "Secrets from Vault"
    data_hash: vault_hiera_hash
    uris:
      - "https://vault.example.com:8200/v1/puppet/nodes/%{fqdn}"  # Node specific secrets
      - "https://vault.example.com:8200/v1/puppet/common"         # Secrets common to all nodes
    options:
      timeout: 3
      token_file: "/etc/puppetlabs/puppet/.vault-token"           # File contains the Vault token
      ca_trust: "/etc/ssl/certs/ca-certificates.crt"
```

## Limitations

Should work with all supported releases of Puppet server, but has been only minimally tested.  Deferred functinos require
Puppet 6 or later.

