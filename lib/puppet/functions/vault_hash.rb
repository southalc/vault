# @summary Return a hash from a Vault key/value secrets engine path
#
Puppet::Functions.create_function(:vault_hash) do
  # @param vault_uri The full URI to the Vault API endpoint for a key/value secrets engine path.
  # @param auth_path The Vault mount path of the 'cert' authentication type used with Puppet certificates.
  # @param version Set this value to 'v2' to use version 2 of the Vault key/value secrets engine.
  # @param timeout Value in seconds to wait for Vault connections.
  # @param ca_trust The path to the trusted certificate authority chain file
  # @return [Hash] Contains all the key/value pairs from the given path.
  dispatch :vault_hash do
    required_param 'String', :vault_uri
    required_param 'String', :auth_path
    optional_param 'String', :version
    optional_param 'Integer', :timeout
    optional_param 'String', :ca_trust
  end

  require "#{File.dirname(__FILE__)}/../../puppet_x/vault_secrets/vault.rb"

  def vault_hash(vault_uri, auth_path, version = 'v1', timeout = 5, ca_trust = nil)
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
    vault.get(URI(vault_uri).path, version)
  end
end
