# @summary Structured fact about the managed host PKI certificate and private key

require 'facter'
require 'date'

Facter.add(:vault_cert) do
  confine osfamily: 'RedHat'

  setcode do
    '/etc/pki/vault-secerts'
  end
end

Facter.add(:vault_cert) do
  confine osfamily: 'Debian'

  setcode do
    '/etc/ssl/vault-secerts'
  end
end


