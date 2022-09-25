# @summary Custom fact defines the location where vault_cert files will be located.

require 'facter'

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
