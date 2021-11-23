# vault_secrets

## Table of Contents

1. [Description](#description)
1. [Vault Setup](#setup)
1. [Usage](#usage)
1. [Reference](#reference)
1. [Limitations](#limitations)
1. [Development](#development)

## Description

This module provides functions, types, and providers to integrate Hashicorp Vault with Puppet, and uses the main module
class to enable issuing and renewing host certificates from a Vault PKI secrets engine.  If you only want to use the
functions without issuing host certificates from Vault, add the module to an environment without assigning it to any nodes.

The custom hiera backend `vault_hiera_hash` enables the puppet server to use a Vault key/value secrets engine as a hiera
data_hash.  This allows storing multiple key/value pairs on a given Vault path and using it from hiera much like local
YAML files.  The function supports both v1 and v2 of the Vault key/value secrets engine and is useful to easily separate
secrets from other version controlled hiera data. The `vault_secrets::approle_agent` plan can be used to obtain a Vault
token for use with hiera, or the Puppet certificate can be used for certificate authentication to Vault.

The `vault_hash` and `vault_key` functions also support Vault key/value secrets engines version 1 and 2 and can be used
in manifests to get secrets from Vault.  With Puppet agents 6 and later you can also use
[deferred functions](https://puppet.com/docs/puppet/latest/deferred_functions.html) to enable clients to get secrets
directly from Vault without passing them through the Puppet server in a catalog.

The `vault_cert` custom resource type can be used to manage TLS certificates for use by other applications.  These are
issued by Vault directly to agents (private keys are not stored on puppet servers or in the catalog), and renewed
automatically as needed.  Note that this requires puppet agents to authenticate to Vault using the agent certificate
and request a Vault certificate from a configured role on a PKI secrets engine.

## Setup

The module does not require any extra ruby gems on the Puppet server or agents.  Obviously you need to have a working
Hashicorp Vault deployment first.  The following describes a basic Vault configuration to support puppet integration.

Complete the following steps on the Vault server:

1. Enable a kv secrets engine on path 'puppet/'.  This example is for version 1 of the k/v engine:
```
vault secrets enable -path=puppet -description="Puppet data" -version=1 kv
```

2. Use the Vault UI or command line to create a secret under the 'puppet/' path.  This example will use the name "common"
as the secret name for storing key/value secrets common to all nodes.

3. Configure Vault to enable authentication with certificates issued by the puppet certificate authority.  From a puppet
node you can reference the puppet CA certificate from: '/etc/puppetlabs/puppet/ssl/certs/ca.pem'.  When using PKI
authentication, the module functions will authenticate every Vault request independently, so use a low "ttl" value to
keep from building up many active Vault tokens.  You can skip this step if you only want to use Vault as a backend for
hiera and will not be using deferred functions or the `vault_cert` type.

```
vault auth enable -path=puppet-pki -description="PKI authentication with Puppet certificates" cert
vault write auth/puppet-pki/certs/puppetCA \
  display_name="Puppet CA" \
  policies=puppet \
  certificate=@/etc/puppetlabs/puppet/ssl/certs/ca.pem \
  ttl=60
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
results in a separate Vault request and will incur some overhead on the Puppet server.
```
hierarchy:
  - name: "Secrets from Vault"
    data_hash: vault_hiera_hash
    uri: "https://vault.example.com:8200/v1/puppet/common"   # Secrets common to all nodes
    options:
      timeout: 3
      auth_path: "puppet-pki"
```
Example configuration using Vault for hiera data using multiple search paths and a pre-staged Vault token to avoid
authentication overhead with each lookup.  When using a Vault token, ensure the 'token_file' has read permissions by
the user running the Puppet server process.  Obviously this is a security sensitive file that should be protected from
all other access.  A Vault agent with an app role is useful for this.
```
hierarchy:
  - name: "Secrets from Vault"
    data_hash: vault_hiera_hash
    uris:
      - "https://vault.example.com:8200/v1/puppet/nodes/%{fqdn}"  # Node specific secrets
      - "https://vault.example.com:8200/v1/puppet/common"         # Secrets common to all nodes
    options:
      token_file: "/run/vault-puppet/puppetserver.token"          # Sink file from 'vault_secrets::approle_agent' plan
```

### Vault agent for use with the hiera backend

The Vault AppRole method is used by applications to authenticate to Vault and obtain
a token.  An AppRole defines a token policy and will issue a token when an application
authenticates to the AppRole using the role ID and secret ID.  The following steps will
enable an AppRole on Vault for use with hiera lookup from the Puppet server:

1. Enable the AppRole authentiation method:
```bash
vault auth enable approle
```

2. Define an app role by specifying the token policies and TTL (period).  Note that a periodic
token is the only type that may be renewed indefinately, which is what we want for long-running
application services like hiera on Puppet.  We will re-use the "puppet" policy defined in the
previous Vault setup steps:
```bash
vault write auth/approle/role/puppet policies="puppet" period="24h"
```

3. Get the role ID for the defined role:
```bash
vault read -format=json auth/approle/role/puppet/role-id | jq -r ".data.role_id"
```

4. Generate a secret ID for the role:
```bash
vault write -f -format=json auth/approle/role/puppet/secret-id | jq -r ".data.secret_id"
```

5. Authenticating to the AppRole with the role ID and secret ID results in a token being issued
per the assigned role policy.  This step is shown just for demonstration purposes:
```bash
vault write auth/approle/login role_id=<role_id> secret_id=<secret_id>
```

With the Vault AppRole in place we can configure the Puppet server to perform hiera lookups
from Vault using a token issed by the AppRole to a Vault agent.  This is more efficient than
using Puppet certificates to authenticate to Vault for every request.  To simplify configuration
of the Vault agent, the module includes the defined type "vault_secrets::approle_agent" and
a plan of the same name.  The plan and type can install Vault and configure the Vault agent using
an existing AppRole.  The Vault agent will be configured to run as a systemd service to ensure
it starts automatically on boot-up and the token will be available for hiera lookups. The Vault
agent service also handles renewal of the token as needed.

You can use the defined type in Puppet manifests to deploy Vault agents to nodes, but the
"role_id" and "secret_id" values are sensitive and should be probably be stored in Vault.
To deploy the Vault agent to the puppet server itself without storing these values in hiera,
run the plan either with Bolt or from the PE console.

If you haven't used [Bolt](https://puppet.com/docs/bolt/latest/bolt.html) to run plans before, you'll need to:

1. Initialize a project directory with the required modules:
```bash
mkdir approle_agent
cd approle_agent
bolt project init approle_agent --modules southalc/vault_secrets
```

2. Update the project [inventory.yaml](https://puppet.com/docs/bolt/latest/inventory_files.html)
to include the targets you want to manage.

3. Run the plan.  This example configures a Vault agent on server "puppet.example.com" with the
sink file owner set to "pe-puppet".  The sink file is where the Vault token will be saved and
uses a fixed path of "/run/vault-${owner}/${application}.token" where "owner" and "application"
are the values passed to the plan:
```
bolt plan run vault_secrets::approle_agent \
 --targets puppet.example.com \
 'vault_addr=https://vault.example.com:8200' \
 role_id=<YOUR_ROLE_ID> \
 secret_id=<YOUR_SECRET_ID> \
 application=puppetserver \
 owner=puppet \
 --run-as root 
```

Note that the "vault_secrets::approle_agent" type and plan rely on systemd and will only
work on Linux systems.  Also, automatic Vault installation will only work for RedHat and Debian
variants supported by [hashi_stack](https://forge.puppet.com/modules/puppet/hashi_stack).

### Vault-issued certificates directly to nodes

Include the `vault_secrets::vault_cert` class to ensure required directories are created
and then use the `vault_cert` resource type for each certificate you wish to manage.
This resource will authenticate to vault using the agent's Puppet certificate, and write
the key, certificate and chain files so they can be consumed by another application.
The private key is written only on the agent, and is not revealed to the puppet server
or included in the catalog.

Certificates will be renewed automatically when puppet runs and there are fewer days
remaining than the `renewal_threshold` parameter is set to, or if the certificate is
found to already be expired.

By default, all files are written to the directory specified by the `$::vault_cert_dir`
fact, however the issued certificate and key files can be written to arbitrary locations.
File ownership and permissions can also be customised as shown below.

```puppet
include vault_secrets::vault_cert

vault_cert { 'test':
  ensure            => present,
  vault_uri         => 'https://vault.example.com:8200/pki/issue/role',
  cert_data         => {
    'common_name' => 'test.example.com',
    'alt_names'   => ['alias.exmaple.com', 'localhost'].join('\n'),
    'ip_sans'     => [$::facts['networking']['ip'], '127.0.0.1'],
    'ttl'         => '2160h', # 90 days
  },
  # Optional
  renewal_threshold => 5,
  ca_chain_file     => '/srv/myapp/ca.crt',
  ca_chain_owner    => 'myapp',
  ca_chain_group    => 'myapp',
  cert_file         => '/srv/myapp/server.crt',
  cert_owner        => 'myapp',
  cert_group        => 'myapp',
  key_file          => '/srv/myapp/server.key',
  key_owner         => 'myapp',
  key_group         => 'myapp',
}
```

You can purge certificates from the system which are no longer included in the puppet
catalog by setting `vault_sercrets::vault_cert::purge: true` in hiera, or like the below:

```puppet
class { 'vault_secrets::vault_cert':
  purge => true,
}
```

`vault_cert` resources will autorequire any `File` resources coresponding to
the parent directories of the `ca_chain_file`, `cert_file` and `key_file` properties. Any `User` or `Group` resources corresponding to the `*_owner` or `*_group` properties will also be autorequired.

## Limitations

Should work with all supported releases of Puppet server, but has been only minimally tested.  Deferred functinos require
Puppet 6 or later.

