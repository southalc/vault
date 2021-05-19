# @summary Return a hash from a Vault key/value secrets engine path
#
Puppet::Functions.create_function(:vault_hash) do
  # @param vault_uri The full URI to the Vault API endpoint for a key/value secrets engine path.
  # @param auth_path The Vault mount path of the 'cert' authentication type used with Puppet certificates.
  # @param version Set this value to 'v2' to use version 2 of the Vault key/value secrets engine.
  # @param timeout Value in seconds to wait for Vault connections.
  # @return [Hash] Contains all the key/value pairs from the given path.
  dispatch :vault_hash do
    required_param 'String', :vault_uri
    required_param 'String', :auth_path
    optional_param 'String', :version
    optional_param 'Integer', :timeout
  end

  require "#{File.dirname(__FILE__)}/../shared/vault_common.rb"

  def vault_hash(vault_uri, auth_path, version = 'v1', timeout = 5)
    uri = URI(vault_uri)
    raise Puppet::Error, "Unable to parse a hostname from #{vault_uri}" unless uri.hostname

    # Try known paths for trusted CA certificate bundles
    ca_trust = if File.exist?('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')
                 '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
               elsif File.exist?('/etc/ssl/certs/ca-certificates.crt')
                 '/etc/ssl/certs/ca-certificates.crt'
               else
                 nil
               end
    raise Puppet::Error, 'Failed to get the trusted CA certificate file' if ca_trust.nil?

    http = http_create_secure(uri, ca_trust, timeout)
    token = vault_get_token(http, auth_path.delete('/'))
    secrets = vault_http_get(http, uri.path, token)
    vault_parse_data(secrets, version)
  end
end
