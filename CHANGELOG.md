# Changelog

## Release 0.6.0

- Certificate chain with intermediate authority #17. Requested by Enucatl

## Release 0.5.2

Bugfix - Enable the vault-token service service in the approle_agent

## Release 0.5.1

Bugfix - Data type correction.  Contributed by luckyraul

## Release 0.5.0

- New 'vault_ssh_cert' custom type to manage signed SSH host keys with Vault.  Contributed by optiz0r.

## Release 0.4.5

- Make fail_hard configurable from vault_hiera_hash #11.  Contributed by gibbs
- Include full URLs in failure messages instead of just the relative path.

## Release 0.4.4

Bugfix - Rename the "Vault" ruby class to avoid naming conflicts with Puppet module "jsok/vault".

## Release 0.4.3

Bugfix - Use gsub instead of delete_prefix to support older puppet/ruby versions.  Contributed by dmaes

## Release 0.4.2

- Update the 'vault_cert' provider handling for certificate expiration.  Contributed by optiz0r.

## Release 0.4.1

- Update approle_agent so the systemd "vault-token" service will use "oneshot" instead of
  "simple".  Contributed by dmaes 

## Release 0.4.0

- Add defined type "vault_secrets::approle_agent" to configure a Vault agent for use with an
  existing AppRole and save the Vault token to a fixed sink file.
- Add plan "vault_secrets::approle_agent" to apply the defined type on targets

## Release 0.3.2

Bugfix - Update post method in the Vault ruby class to use request.body instead of request.set_form_data
Bugfix - The puppet "vault_secrets" class should handle "unknown" as the value of "days_remaining"

## Release 0.3.1

- Refactor shared functions as a ruby class and update references

## Release 0.3.0

- Added custom provider with the 'vault_cert' type to enable puppet nodes to directly
  manage a Vault certificate without the request being issued through the puppet master
  and being stored in the catalog.  Contributed by optiz0r.

## Release 0.2.1

Bugfix - Module hiera update for new module name

## Release 0.2.0

- Module renamed to "vault_secrets" to avoid naming conflict
- Updated error handling in functions
- vault_hiera_hash function now uses 'token_file' instead of 'token'

## Release 0.1.1

Bugfix - Set 'show_diff' to false when updating certificate and private key file content

## Release 0.1.0

Initial release - See README for features

