Puppet::Type.newtype(:vault_ssh_cert) do
  @doc = 'A type representing an SSH certificate issued by Hashicorp Vault'
  ensurable

  newparam(:name) do
    desc 'Path to the public key the certificate should be issued for'
    isnamevar
  end

  newparam(:vault_uri) do
    desc 'The full URI of the vault PKI secrets engine'
    isrequired
  end

  newparam(:auth_path) do
    desc 'The path used to authenticate puppet agent to vault'
    defaultto 'puppet-pki'
  end

  newparam(:auth_name) do
    desc 'The named certificate role used to authenticate puppet agent to vault'
    # defaults to unset, which means vault will try to match the client
    # against all defined certificate roles. It may be necessary to set this
    # if a client would match multiple roles to ensure the correct one is used
    # defaultto nil
  end

  newparam(:timeout) do
    desc 'Length of time to wait on vault connections'
    defaultto 5
  end

  newparam(:renewal_threshold) do
    desc 'Certificate should be renewed when fewer than this many days remain before expiry'
    defaultto 3
  end

  newparam(:ttl) do
    desc 'Lifetime to request any newly issued certificates should be valid for'
  end

  newparam(:cert_type) do
    desc 'Cert type to issue ("user" or "host")'
    defaultto 'host'
    validate do |value|
      unless ['user', 'host'].include? value
        raise ArgumentError, "#{value} is not a valid cert_type"
      end
    end
  end

  newproperty(:valid_principals, array_matching: :all) do
    desc 'Users or hostnames which the issued certificate should be valid for'
    defaultto []
    validate do |value|
      unless value.is_a?(String)
        raise ArgumentError, 'All valid_principals values must be Strings.'
      end
    end
  end

  newproperty(:file) do
    desc 'Path the signed certificate should be written'
    defaultto do
      @resource[:name].sub(%r{(\.pub)?$}, '-cert\1')
    end
  end

  newproperty(:owner) do
    desc 'The user which the certificate file should be owned by'
    defaultto 'root'
  end

  newproperty(:group) do
    desc 'The group which the certificate file should be owned by'
    defaultto 'root'
  end

  newproperty(:mode) do
    desc 'The file mode the certificate file should be written with'
    defaultto '0640'
  end

  newproperty(:expiration) do
    desc 'Read-only property showing the expiration time of the certificate'
    newvalues(:auto)
    defaultto :auto

    def insync?(_is)
      !provider.expires_soon_or_expired
    end
  end

  autorequire(:file) do
    [self[:file]]
  end

  autorequire(:user) do
    [self[:owner]]
  end

  autorequire(:group) do
    [self[:group]]
  end
end
