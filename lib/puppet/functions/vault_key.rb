# @summary Return the value from a Vault key/value secrets engine from a given path and key
#
Puppet::Functions.create_function(:vault_key) do
  # @param vault_uri The complete API path to a Vault key/value secret
  # @param auth_path The Vault mount path of the "cert" authentication type used with Puppet certificates.
  # @param key The name of a specific secret at the given 'vault_uri'
  # @param version Set this value to 'v2' to use version 2 of the Vault key/value secrets engine
  # @param timeout Value in seconds to wait for a response from Vault
  # @return [String] The value of the secret from the @vault_uri and @key
  dispatch :vault_key do
    required_param 'String', :vault_uri
    required_param 'String', :auth_path
    required_param 'String', :key
    optional_param 'String', :version
    optional_param 'Integer', :timeout
  end

  require "#{File.dirname(__FILE__)}/../shared/vault_common.rb"

  def vault_key(vault_uri, auth_path, key, version = 'v1', timeout = 5)
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
    data = vault_parse_data(secrets, version)

    raise Puppet::Error, "Key #{key} not found at Vault path #{uri.path}" unless data.key?(key)

    data[key]
  end
end
