# @summary Obtain a host certificate from a Vault PKI secrets engine
#
Puppet::Functions.create_function(:vault_cert) do
  # @param vault_uri The complete API path to a Vault PKI role for issuing certificates.
  # @param auth_path The Vault mount path of the "cert" authentication type used with Puppet certificates.
  # @param data A hash of values to be submitted with a certificate request.  The hash contents
  #   must adhere to the constructs of the Vault PKI role and policy being used at the 'vault_uri' endpoint.
  # @param timeout Value in seconds to wait for Vault connections.  Default is 5.
  # @return [Hash] The returned hash contains the certificate, private key, and supporting data
  dispatch :vault_cert do
    required_param 'String', :vault_uri
    required_param 'String', :auth_path
    required_param 'Hash', :data
    optional_param 'Integer', :timeout
  end

  require "#{File.dirname(__FILE__)}/../shared/vault_common.rb"

  def vault_cert(vault_uri, auth_path, data, timeout = 5)
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
    secrets = vault_http_post(http, uri.path, token, data)
    vault_parse_data(secrets)
  end
end
