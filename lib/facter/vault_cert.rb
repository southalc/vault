# @summary Structured fact about the managed host PKI certificate and private key

require 'facter'
require 'date'

Facter.add(:vault_cert) do
  confine osfamily: 'RedHat'

  setcode do
    result = {}
    hostname = Facter.value(:hostname)
    cert_dir = '/etc/pki/tls'
    host_cert = File.join(cert_dir, 'certs', "#{hostname}.pem")
    host_key = File.join(cert_dir, 'private', "#{hostname}.key")
    result['cert'] = host_cert
    result['key'] = host_key
    result['ca_chain'] = '/etc/pki/ca-trust/source/anchors/vault_chain.pem'
    if File.file?(host_cert) && File.file?(host_key)
      cert_m = Facter::Core::Execution.execute("openssl x509 -in #{host_cert} -noout -modulus", on_fail: nil)
      key_m = Facter::Core::Execution.execute("openssl rsa -in #{host_key} -noout -modulus", on_fail: nil)
      unless cert_m.nil? || key_m.nil?
        cert_modulus = cert_m.strip.split('=')[-1]
        key_modulus = key_m.strip.split('=')[-1]
        result['valid'] = if cert_modulus == key_modulus
                            true
                          else
                            false
                          end
      end
      cert_dates = Facter::Core::Execution.execute("openssl x509 -in #{host_cert} -noout -dates", on_fail: nil)
      unless cert_dates.nil?
        begin
          expiration = Date.parse(cert_dates.split(%r{\n})[-1].split('=')[-1].strip)
          days_remaining = Integer(expiration - Date.today)
        rescue
          expiration = 'unknown'
          days_remaining = 'unknown'
        end
        result['expiration'] = expiration
        result['days_remaining'] = days_remaining
      end
    else
      result['valid'] = false
    end
    result
  end
end

Facter.add(:vault_cert) do
  confine osfamily: 'Debian'

  setcode do
    result = {}
    hostname = Facter.value(:hostname)
    cert_dir = '/etc/ssl'
    host_cert = File.join(cert_dir, 'certs', "#{hostname}.crt")
    host_key = File.join(cert_dir, 'private', "#{hostname}.key")
    result['cert'] = host_cert
    result['key'] = host_key
    result['ca_chain'] = '/etc/ssl/certs/vault_chain.pem'
    if File.file?(host_cert) && File.file?(host_key)
      cert_m = Facter::Core::Execution.execute("openssl x509 -in #{host_cert} -noout -modulus", on_fail: nil)
      key_m = Facter::Core::Execution.execute("openssl rsa -in #{host_key} -noout -modulus", on_fail: nil)
      unless cert_m.nil? || key_m.nil?
        cert_modulus = cert_m.strip.split('=')[-1]
        key_modulus = key_m.strip.split('=')[-1]
        result['valid'] = if cert_modulus == key_modulus
                            true
                          else
                            false
                          end
      end
      cert_dates = Facter::Core::Execution.execute("openssl x509 -in #{host_cert} -noout -dates", on_fail: nil)
      unless cert_dates.nil?
        begin
          expiration = Date.parse(cert_dates.split(%r{\n})[-1].split('=')[-1].strip)
          days_remaining = Integer(expiration - Date.today)
        rescue
          expiration = 'unknown'
          days_remaining = 'unknown'
        end
        result['expiration'] = expiration
        result['days_remaining'] = days_remaining
      end
    else
      result['valid'] = false
    end
    result
  end
end
