# frozen_string_literal: true

# Return a hash from a Vault key/value secrets engine path
Puppet::Functions.create_function(:vault_hash) do
  # @param vault_uri The full URI to the Vault API endpoint for a key/value secrets engine path.
  # @param auth_path The Vault mount path of the 'cert' authentication type used with Puppet certificates.
  # @param version Set this value to 'v2' to use version 2 of the Vault key/value secrets engine.
  # @param timeout Value in seconds to wait for Vault connections.
  # @param ca_trust The path to the trusted certificate authority chain file.  Some OS defaults will be attempted if nil.
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
    connection = {
      'uri'       => vault_uri,
      'auth_path' => auth_path,
      'ca_trust'  => ca_trust,
      'timeout'   => timeout,
    }

    # Use the Vault class for the lookup
    vault = Vault.new(connection)
    vault.get(URI(vault_uri).path, version)
  end
end
