# @summary Structured fact about the managed host PKI certificate and private key

require 'facter'
require 'date'

Facter.add(:vault_cert_dir) do
  confine osfamily: 'RedHat'

  setcode do
    '/etc/pki/vault-secrets'
  end
end

Facter.add(:vault_cert_dir) do
  confine osfamily: 'Debian'

  setcode do
    '/etc/ssl/vault-secrets'
  end
end
