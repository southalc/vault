# @summary Structured fact about the managed host PKI certificate and private key

require 'facter'
require 'date'
require 'openssl'

def vault_secrets_read_cert(file)
  # Obtain the X509 certificate from source file
  OpenSSL::X509::Certificate.new(File.read(file))
rescue
  nil
end

def vault_secrets_read_key(file)
  # Obtain the RSA private key from source file
  OpenSSL::PKey::RSA.new(File.read(file))
rescue
  nil
end

def vault_secrets_cert_valid(cert, key)
  # Return a boolean if the given cert/key files are a valid pair
  cert.check_private_key key
rescue
  false
end

def vault_secrets_cert_dates(cert)
  # Return a hash with the certificate expiration date and the number of days until expiration
  result = {}
  begin
    expiration = cert.not_after.to_date
    result['expiration'] = expiration.strftime('%Y-%m-%d')
    result['days_remaining'] = Integer(expiration - Date.today)
  rescue
    result['expiration'] = 'unknown'
    result['days_remaining'] = 'unknown'
  end
  result
end

Facter.add(:vault_cert) do
  confine { Facter.value(:os)['name'] == 'RedHat' }
  has_weight 100

  setcode do
    result = {}
    hostname = Facter.value(:hostname)
    cert_dir = '/etc/pki/tls'
    result['cert'] = File.join(cert_dir, 'certs', "#{hostname}.pem")
    result['key'] = File.join(cert_dir, 'private', "#{hostname}.key")
    result['ca_chain'] = '/etc/pki/ca-trust/source/anchors/vault_chain.pem'
    cert = vault_secrets_read_cert(result['cert'])
    key = vault_secrets_read_key(result['key'])
    result['valid'] = vault_secrets_cert_valid(cert, key)
    cert_dates = vault_secrets_cert_dates(cert)
    result['expiration'] = cert_dates['expiration']
    result['days_remaining'] = cert_dates['days_remaining']
    result
  end
end

Facter.add(:vault_cert) do
  confine { Facter.value(:os)['name'] == 'Debian' }
  has_weight 100

  setcode do
    result = {}
    hostname = Facter.value(:hostname)
    cert_dir = '/etc/ssl'
    result['cert'] = File.join(cert_dir, 'certs', "#{hostname}.crt")
    result['key'] = File.join(cert_dir, 'private', "#{hostname}.key")
    result['ca_chain'] = '/etc/ssl/certs/vault_chain.pem'
    cert = vault_secrets_read_cert(result['cert'])
    key = vault_secrets_read_key(result['key'])
    result['valid'] = vault_secrets_cert_valid(cert, key)
    cert_dates = vault_secrets_cert_dates(cert)
    result['expiration'] = cert_dates['expiration']
    result['days_remaining'] = cert_dates['days_remaining']
    result
  end
end

Facter.add(:vault_cert) do
  # Values for operating systems other than RedHat/Debian distributions
  has_weight 50

  setcode do
    result = {}
    hostname = Facter.value(:hostname)
    cert_dir = '/etc/vault_cert'
    result['cert'] = File.join(cert_dir, "#{hostname}.pem")
    result['key'] = File.join(cert_dir, "#{hostname}.key")
    result['ca_chain'] = File.join(cert_dir, 'ca_chain.pem')
    cert = vault_secrets_read_cert(result['cert'])
    key = vault_secrets_read_key(result['key'])
    result['valid'] = vault_secrets_cert_valid(cert, key)
    cert_dates = vault_secrets_cert_dates(cert)
    result['expiration'] = cert_dates['expiration']
    result['days_remaining'] = cert_dates['days_remaining']
    result
  end
end
