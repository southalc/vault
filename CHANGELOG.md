# Changelog

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
