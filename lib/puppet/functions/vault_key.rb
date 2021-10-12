# @summary Return the value from a Vault key/value secrets engine from a given path and key
#
Puppet::Functions.create_function(:vault_key) do
  # @param vault_uri The complete API path to a Vault key/value secret
  # @param auth_path The Vault mount path of the "cert" authentication type used with Puppet certificates.
  # @param key The name of a specific secret at the given 'vault_uri'
  # @param version Set this value to 'v2' to use version 2 of the Vault key/value secrets engine
  # @param timeout Value in seconds to wait for a response from Vault
  # @param ca_trust The path to the trusted certificate authority chain file
  # @return [String] The value of the secret from the @vault_uri and @key
  dispatch :vault_key do
    required_param 'String', :vault_uri
    required_param 'String', :auth_path
    required_param 'String', :key
    optional_param 'String', :version
    optional_param 'Integer', :timeout
    optional_param 'String', :ca_trust
  end

  require "#{File.dirname(__FILE__)}/../../puppet_x/vault_secrets/vault.rb"

  def vault_key(vault_uri, auth_path, key, version = 'v1', timeout = 5, ca_trust = nil)
    # Try known paths for trusted CA certificates when not specified
    ca_file = if ca_trust && File.exist?(ca_trust)
                ca_trust
              elsif File.exist?('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')
                '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
              elsif File.exist?('/etc/ssl/certs/ca-certificates.crt')
                '/etc/ssl/certs/ca-certificates.crt'
              else
                nil
              end
    raise Puppet::Error, 'Failed to get the trusted CA certificate file' if ca_file.nil?

    connection = {
      'uri'       => vault_uri,
      'auth_path' => auth_path,
      'ca_trust'  => ca_file,
      'timeout'   => timeout,
    }

    # Use the Vault class for the lookup
    vault = Vault.new(connection)
    data = vault.get(URI(vault_uri).path, version)
    raise Puppet::Error, "Key #{key} not found at Vault path #{vault_uri}" unless data.key?(key)
    data[key]
  end
end
