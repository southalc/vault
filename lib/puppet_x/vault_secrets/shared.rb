# ruby functions shared by module puppet functions

def get_ca_file(ca_trust)
  # @summary Try known paths for trusted CA certificates when not specified
  # @param ca_trust The path to a trusted certificate authority file. If nil, some defaults are attempted
  # @return The verified file path to a trusted certificate authority file
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
  ca_file
end
