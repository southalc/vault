Puppet::Type.newtype(:vault_cert) do
  @doc = 'A type representing a certificate issued by Hashicorp Vault'
  ensurable

  newparam(:name) do
    isnamevar
    desc 'The name of the certificate'
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

  newparam(:token) do
    desc 'The token used to authenticate puppet agent to vault'
  end

  newparam(:ca_trust) do
    desc 'Optional path to the file containing trusted certificate authorities'
    # defaults to unset, which means the client will attempt to use the default
    # system trust on RedHat or Debian based distributions. Any other operating
    # systems will need supply a value.
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

  newproperty(:cert_data) do
    desc 'The attributes of the certificate to be issued'
    isrequired
  end

  # Info file

  newproperty(:info_owner) do
    desc 'The user which the info_file should be owned by'
    defaultto 'root'
  end

  newproperty(:info_group) do
    desc 'The group which the info_file should be owned by'
    defaultto 'root'
  end

  newproperty(:info_mode) do
    desc 'The file mode the info_file should be written with'
    defaultto '0600'
  end

  # CA Chain

  newproperty(:cert_chain_file) do
    desc 'Where the CA chain file should be written'
    defaultto do
      cert_dir = Facter.value(:vault_cert_dir)
      "#{cert_dir}/#{@resource[:name]}.chain.crt"
    end
  end

  newproperty(:cert_chain_owner) do
    desc 'The user which the cert_chain_file should be owned by'
    defaultto 'root'
  end

  newproperty(:cert_chain_group) do
    desc 'The group which the cert_chain_file should be owned by'
    defaultto 'root'
  end

  newproperty(:cert_chain_mode) do
    desc 'The file mode the cert_chain_file should be written with'
    defaultto '0644'
  end

  newproperty(:cert_chain) do
    desc 'Read-only property which contains the value of the CA chain'
    newvalues(:auto)
    defaultto :auto

    def insync?(is)
      is == resource.property(:info_cert_chain).retrieve
    end
  end

  newproperty(:info_cert_chain) do
    desc 'Read-only property which contains the value of the CA chain from the info file'
    newvalues(:auto)
    defaultto :auto

    def insync?(_is)
      true
    end
  end

  # Certificate

  newproperty(:cert_file) do
    desc 'Where the certificate file should be written'
    defaultto do
      cert_dir = Facter.value(:vault_cert_dir)
      "#{cert_dir}/#{@resource[:name]}.crt"
    end
  end

  newproperty(:cert_owner) do
    desc 'The user which the cert_file should be owned by'
    defaultto 'root'
  end

  newproperty(:cert_group) do
    desc 'The group which the cert_file should be owned by'
    defaultto 'root'
  end

  newproperty(:cert_mode) do
    desc 'The file mode the cert _file should be written with'
    defaultto '0644'
  end

  newproperty(:cert) do
    desc 'Read-only property which contains the value of the certificate'
    newvalues(:auto)
    defaultto :auto

    def insync?(is)
      is == resource.property(:info_cert).retrieve
    end
  end

  newproperty(:info_cert) do
    desc 'Read-only property which contains the value of the cerificate from the info file'
    newvalues(:auto)
    defaultto :auto

    def insync?(_is)
      true
    end
  end

  # Private Key

  newproperty(:key_file) do
    desc 'Where the key file should be written'
    defaultto do
      cert_dir = Facter.value(:vault_cert_dir)
      "#{cert_dir}/#{@resource[:name]}.key"
    end
  end

  newproperty(:key_owner) do
    desc 'The user which the key_file should be owned by'
    defaultto 'root'
  end

  newproperty(:key_group) do
    desc 'The group which the key_file should be owned by'
    defaultto 'root'
  end

  newproperty(:key_mode) do
    desc 'The file mode the key file should be written with'
    defaultto '0600'
  end

  newproperty(:info_key) do
    desc 'Read-only property which contains the value of the private key from the info file'
    newvalues(:auto)
    defaultto :auto
    # sensitive true

    def insync?(_is)
      true
    end
  end

  newproperty(:key) do
    desc 'Read-only property which contains the value of the privat ekey'
    newvalues(:auto)
    defaultto :auto
    sensitive true

    def insync?(is)
      is == resource.property(:info_key).retrieve
    end
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
    [
      Facter.value(:vault_cert_dir),
      File.dirname(self[:cert_chain_file]),
      File.dirname(self[:cert_file]),
      File.dirname(self[:key_file]),
    ].uniq
  end

  autorequire(:user) do
    [
      self[:cert_chain_owner],
      self[:cert_owner],
      self[:key_owner],
    ].uniq
  end

  autorequire(:group) do
    [
      self[:cert_chain_group],
      self[:cert_group],
      self[:key_group],
    ].uniq
  end
end
