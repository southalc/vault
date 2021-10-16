# frozen_string_literal: true

# Obtain a host certificate from a Vault PKI secrets engine
Puppet::Functions.create_function(:vault_cert) do
  # @summary Obtain a host certificate from a Vault PKI secrets engine
  # @param vault_uri The complete API path to a Vault PKI role for issuing certificates.
  # @param auth_path The Vault mount path of the "cert" authentication type used with Puppet certificates.
  # @param data A hash of values to be submitted with a certificate request.  The hash contents
  #   must adhere to the constructs of the Vault PKI role and policy being used at the 'vault_uri' endpoint.
  # @param timeout Value in seconds to wait for Vault connections.  Default is 5.
  # @param ca_trust The path to the trusted certificate authority chain file.  Some OS defaults will be attempted if nil.
  # @return [Hash] The returned hash contains the certificate, private key, and supporting data
  dispatch :vault_cert do
    required_param 'String', :vault_uri
    required_param 'String', :auth_path
    required_param 'Hash', :data
    optional_param 'Integer', :timeout
    optional_param 'String', :ca_trust
  end

  require "#{File.dirname(__FILE__)}/../../puppet_x/vault_secrets/vault.rb"

  def vault_cert(vault_uri, auth_path, data, timeout = 5, ca_trust = nil)
    connection = {
      'uri'       => vault_uri,
      'auth_path' => auth_path,
      'ca_trust'  => ca_trust,
      'timeout'   => timeout,
    }

    # Use the Vault class for the lookup
    vault = Vault.new(connection)
    response = vault.post(URI(vault_uri).path, data)
    vault.parse_response(response)
  end
end
