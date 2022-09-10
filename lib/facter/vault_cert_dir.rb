# @summary Structured fact about the managed host PKI certificate and private key

require 'facter'
require 'date'

Facter.add(:vault_cert_dir) do
  setcode do
    case Facter.value(:osfamily)
    when 'RedHat'
      '/etc/pki/vault-secrets'
    when 'Debian'
      '/etc/ssl/vault-secrets'
    else
      '/etc/vault-secrets'
    end
  end
end
