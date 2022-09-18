# @summary Structured fact about the managed host PKI certificate and private key

require 'facter'
require 'date'

def vault_secrets_cert_matched_pair(cert_file, key_file)
  # Return a boolean if the given cert/key files are a valid pair
  result = false
  if File.file?(cert_file) && File.file?(key_file)
    cert_m = Facter::Core::Execution.execute("openssl x509 -in #{cert_file} -noout -modulus", on_fail: nil)
    key_m = Facter::Core::Execution.execute("openssl rsa -in #{key_file} -noout -modulus", on_fail: nil)
    unless cert_m.nil? || key_m.nil?
      cert_modulus = cert_m.strip.split('=')[-1]
      key_modulus = key_m.strip.split('=')[-1]
      result = if cert_modulus == key_modulus
                 true
               else
                 false
               end
    end
  end
  result
end

def vault_secrets_cert_dates(cert_file)
  # Return a hash with the certificate expiration date and the number of days until expiration
  result = {}
  cert_dates = Facter::Core::Execution.execute("openssl x509 -in #{cert_file} -noout -dates", on_fail: nil)
  begin
    expiration = Date.parse(cert_dates.split(%r{\n})[-1].split('=')[-1].strip)
    days_remaining = Integer(expiration - Date.today)
  rescue
    expiration = 'unknown'
    days_remaining = 'unknown'
  end
  result['expiration'] = expiration
  result['days_remaining'] = days_remaining
  result
end

Facter.add(:vault_cert) do
  confine osfamily: 'RedHat'
  has_weight 100

  setcode do
    result = {}
    hostname = Facter.value(:hostname)
    cert_dir = '/etc/pki/tls'
    host_cert = File.join(cert_dir, 'certs', "#{hostname}.pem")
    host_key = File.join(cert_dir, 'private', "#{hostname}.key")
    result['cert'] = host_cert
    result['key'] = host_key
    result['ca_chain'] = '/etc/pki/ca-trust/source/anchors/vault_chain.pem'
    result['valid'] = vault_secrets_cert_matched_pair(host_cert, host_key)
    cert_dates = vault_secrets_cert_dates(host_cert)
    result['expiration'] = cert_dates['expiration']
    result['days_remaining'] = cert_dates['days_remaining']
    result
  end
end

Facter.add(:vault_cert) do
  confine osfamily: 'Debian'
  has_weight 100

  setcode do
    result = {}
    hostname = Facter.value(:hostname)
    cert_dir = '/etc/ssl'
    host_cert = File.join(cert_dir, 'certs', "#{hostname}.crt")
    host_key = File.join(cert_dir, 'private', "#{hostname}.key")
    result['cert'] = host_cert
    result['key'] = host_key
    result['ca_chain'] = '/etc/ssl/certs/vault_chain.pem'
    result['valid'] = vault_secrets_cert_matched_pair(host_cert, host_key)
    cert_dates = vault_secrets_cert_dates(host_cert)
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
    host_cert = File.join(cert_dir, "#{hostname}.pem")
    host_key = File.join(cert_dir, "#{hostname}.key")
    result['cert'] = host_cert
    result['key'] = host_key
    result['ca_chain'] = File.join(cert_dir, 'ca_chain.pem')
    result['valid'] = vault_secrets_cert_matched_pair(host_cert, host_key)
    cert_dates = vault_secrets_cert_dates(host_cert)
    result['expiration'] = cert_dates['expiration']
    result['days_remaining'] = cert_dates['days_remaining']
    result
  end
end
