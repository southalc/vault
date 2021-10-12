# @summary Obtain a host certificate from a Vault PKI secrets engine
#
Puppet::Functions.create_function(:vault_cert) do
  # @param vault_uri The complete API path to a Vault PKI role for issuing certificates.
  # @param auth_path The Vault mount path of the "cert" authentication type used with Puppet certificates.
  # @param data A hash of values to be submitted with a certificate request.  The hash contents
  #   must adhere to the constructs of the Vault PKI role and policy being used at the 'vault_uri' endpoint.
  # @param timeout Value in seconds to wait for Vault connections.  Default is 5.
  # @param ca_trust The path to the trusted certificate authority chain file
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
    response = vault.post(URI(vault_uri).path, data)
    vault.parse_response(response)
  end
end
