require 'json'
require 'spec_helper'

type_class = Puppet::Type.type(:vault_ssh_cert)
provider_class = type_class.provider(:vault_ssh_cert)

describe provider_class do
  let(:resource) do
    Puppet::Type.type(:vault_ssh_cert).new({ name: '/testfile.pub', provider: described_class.name })
  end
  let(:provider) { resource.provider }

  describe 'when loading existing instances' do
    before :each do
      cert_files = [
        "/etc/ssh/ssh_host_rsa_key-cert.pub",
        "/etc/ssh/ssh_host_ecdsa_key-cert.pub",
      ]

      allow(Dir).to receive(:glob).with("/etc/ssh/ssh_host_*_key-cert.pub").and_return(cert_files)
      cert_files.each do |filename|
        allow(provider_class).to receive(:load_file).with("/etc/ssh/ssh_host_rsa_key-cert.pub").and_return(['root', 'root', '0640'])
        allow(provider_class).to receive(:load_file).with("/etc/ssh/ssh_host_ecdsa_key-cert.pub").and_return(['root', 'root', '0640'])
      end
    end

    describe 'self.instances' do
      it 'returns an aray of SSH certificate instances' do
        allow(provider_class).to receive(:parse_cert_file).and_return(0, [])
        instances = provider_class.instances.map { |x| x.name }
        expect(instances).to contain_exactly("/etc/ssh/ssh_host_rsa_key.pub", "/etc/ssh/ssh_host_ecdsa_key.pub")
      end
    end

    describe 'self.prefetch' do
      it 'associates defined resources in the catalog with corresponding discovered instances on the system' do
        defined_resources = {
          '/etc/ssh/ssh_host_rsa_key.pub'     => type_class.new(name: '/etc/ssh/ssh_host_rsa_key.pub',     provider: provider_class.name),
          '/etc/ssh/ssh_host_ecdsa_key.pub'   => type_class.new(name: '/etc/ssh/ssh_host_ecdsa_key.pub',   provider: provider_class.name),
          '/etc/ssh/ssh_host_ed25519_key.pub' => type_class.new(name: '/etc/ssh/ssh_host_ed25519_key.pub', provider: provider_class.name),
        }
        test1 = provider_class.new(name: '/etc/ssh/ssh_host_rsa_key.pub', ensure: :present)
        test2 = provider_class.new(name: '/etc/ssh/ssh_host_ecdsa_key.pub', ensure: :present)
        test4 = provider_class.new(name: '/etc/ssh/ssh_host_dsa_key.pub', ensure: :present)
        allow(provider_class).to receive(:instances).and_return([test1, test2, test4])
        provider.class.prefetch(defined_resources)
        expect(defined_resources['/etc/ssh/ssh_host_rsa_key.pub'].provider).to be test1
        expect(defined_resources['/etc/ssh/ssh_host_ecdsa_key.pub'].provider).to be test2
        expect(defined_resources['/etc/ssh/ssh_host_ed25519_key.pub'].provider).not_to be test4
      end
    end

    describe 'self.parse_cert_file' do
      it 'parses the expiration date correctly' do
        output = <<-EOF
          test-cert.pub:
              Type: ssh-rsa-cert-v01@openssh.com host certificate
              Public key: RSA-CERT SHA256:xxx123
              Signing CA: RSA SHA256:xxx123 (using rsa-sha2-256)
              Key ID: "vault-puppet-pki-Puppet CA-12345
              Serial: 5642012486324426605
              Valid: from 2022-07-17T20:45:01 to 2022-08-18T20:45:31
              Principals: (none)
              Critical Options: (none)
              Extensions: (none)
          EOF
        allow(provider_class).to receive(:ssh_keygen).with('-L', '-f', 'test-cert.pem').and_return(output)
        expect(provider_class.parse_cert_file('test-cert.pem')[0]).to be Time.new(2022, 8, 18, 20, 45, 31).to_i
      end

      it 'parses an empty principals list' do
        output = <<-EOF
          test-cert.pub:
              Type: ssh-rsa-cert-v01@openssh.com host certificate
              Public key: RSA-CERT SHA256:xxx123
              Signing CA: RSA SHA256:xxx123 (using rsa-sha2-256)
              Key ID: "vault-puppet-pki-Puppet CA-12345
              Serial: 5642012486324426605
              Valid: from 2022-07-17T20:45:01 to 2022-08-18T20:45:31
              Principals: (none)
              Critical Options: (none)
              Extensions: (none)
          EOF
        allow(provider_class).to receive(:ssh_keygen).with('-L', '-f', 'test-cert.pem').and_return(output)
        expect(provider_class.parse_cert_file('test-cert.pem')[1]).to eq([])
      end
      
      it 'parses a single principal' do
        output = <<-EOF
          test-cert.pub:
              Type: ssh-rsa-cert-v01@openssh.com host certificate
              Public key: RSA-CERT SHA256:xxx123
              Signing CA: RSA SHA256:xxx123 (using rsa-sha2-256)
              Key ID: "vault-puppet-pki-Puppet CA-12345
              Serial: 5642012486324426605
              Valid: from 2022-07-17T20:45:01 to 2022-08-18T20:45:31
              Principals:
                      test.example.com
              Critical Options: (none)
              Extensions: (none)
          EOF
        allow(provider_class).to receive(:ssh_keygen).with('-L', '-f', 'test-cert.pem').and_return(output)
        expect(provider_class.parse_cert_file('test-cert.pem')[1]).to eq(['test.example.com'])
      end
      
      it 'parses multiple principals' do
        output = <<-EOF
          test-cert.pub:
              Type: ssh-rsa-cert-v01@openssh.com host certificate
              Public key: RSA-CERT SHA256:xxx123
              Signing CA: RSA SHA256:xxx123 (using rsa-sha2-256)
              Key ID: "vault-puppet-pki-Puppet CA-12345
              Serial: 5642012486324426605
              Valid: from 2022-07-17T20:45:01 to 2022-08-18T20:45:31
              Principals:
                      test.example.com
                      test2.example.com
              Critical Options: (none)
              Extensions: (none)
          EOF
        allow(provider_class).to receive(:ssh_keygen).with('-L', '-f', 'test-cert.pem').and_return(output)
        expect(provider_class.parse_cert_file('test-cert.pem')[1]).to eq(['test.example.com', 'test2.example.com'])
      end
    end
  end

  describe 'self.load_file' do
    it 'returns nil when asked to load nil' do
      expect(File).not_to receive(:exist?)
      expect(File).not_to receive(:read)
      expect(File).not_to receive(:stat)

      expect(provider_class.load_file(nil)).to eq [nil, nil, nil]
    end

    it 'returns nil when asked to load a non-existent file' do
      expect(File).to receive(:exist?).with('/doesnotexist').and_return(false)
      expect(File).not_to receive(:read)
      expect(File).not_to receive(:stat)

      expect(provider_class.load_file('/doesnotexist')).to eq [nil, nil, nil]
    end

    it 'returns file attributes when called for an existing file' do
      file = '/etc/ssh/ssh_host_rsa_key.pub'
      allow(File).to receive(:exist?).with(file).and_return(true)
      allow(File::Stat).to receive(:new).with(file).and_return(instance_double('File::Stat', uid: 123, gid: 123, mode: 0o10644))
      allow(Etc).to receive(:getpwuid).with(123).and_return(instance_double('Passwd', name: 'testuser'))
      allow(Etc).to receive(:getgrgid).with(123).and_return(instance_double('Passwd', name: 'testgroup'))

      expect(provider_class.load_file(file)).to eq [
        'testuser', 'testgroup', '0644'
      ]
    end
  end

  describe 'self.chown_file' do
    it 'does not do anything if both args are nil' do
      expect(File).not_to receive(:chown)
      provider_class.chown_file('/testfile', nil, nil)
    end

    it 'changes file ownership and group when given user and group' do
      expect(Etc).to receive(:getpwnam).with('testuser').and_return(instance_double('Passwd', uid: 123))
      expect(Etc).to receive(:getgrnam).with('testgroup').and_return(instance_double('Passwd', gid: 123))
      expect(File).to receive(:chown).with(123, 123, '/testfile')

      provider_class.chown_file('/testfile', 'testuser', 'testgroup')
    end

    it 'changes file ownership when given user only' do
      expect(Etc).to receive(:getpwnam).with('testuser').and_return(instance_double('Passwd', uid: 123))
      expect(Etc).not_to receive(:getgrnam)
      expect(File).to receive(:chown).with(123, nil, '/testfile')

      provider_class.chown_file('/testfile', 'testuser', nil)
    end

    it 'changes file group when given group only' do
      expect(Etc).not_to receive(:getpwnam)
      expect(Etc).to receive(:getgrnam).with('testgroup').and_return(instance_double('Passwd', gid: 123))
      expect(File).to receive(:chown).with(nil, 123, '/testfile')

      provider_class.chown_file('/testfile', nil, 'testgroup')
    end
  end

  describe 'self.chmod_file' do
    it 'does not change file permissions if given nil' do
      expect(File).not_to receive(:chmod)
      provider_class.chmod_file('/testfile', nil)
    end

    it 'changes the file permissions with the correct mode when given 0600' do
      expect(File).to receive(:chmod).with(0o600, '/testfile')
      provider_class.chmod_file('/testfile', '0600')
    end

    it 'changes the file permissions with the correct mode when given 0644' do
      expect(File).to receive(:chmod).with(0o644, '/testfile')
      provider_class.chmod_file('/testfile', '0644')
    end
  end

  describe 'self.delete_if_exists' do
    it 'does not delete file if given nil' do
      expect(File).not_to receive(:exist?)
      expect(File).not_to receive(:delete)

      provider_class.delete_if_exists(nil)
    end

    it 'does not delete file if given empty string' do
      expect(File).not_to receive(:exist?)
      expect(File).not_to receive(:delete)

      provider_class.delete_if_exists('')
    end

    it "does not try to delete file if if it doesn't exist" do
      expect(File).to receive(:exist?).with('/testfile').and_return(false)
      expect(File).not_to receive(:delete)

      provider_class.delete_if_exists('/testfile')
    end

    it 'deletes a valid existing file' do
      expect(File).to receive(:exist?).with('/testfile').and_return(true)
      expect(File).to receive(:delete).with('/testfile')

      provider_class.delete_if_exists('/testfile')
    end
  end

  describe 'expires_soon_or_expired' do
    let(:reference_time) { 1_609_459_200 }  # Midnight 1st Jan 2021

    before :each do
      expect(Time).to receive(:now).and_return(instance_double('Time', to_i: reference_time))
    end

    it 'returns false if expiry time is far in the future' do
      resource = type_class.new(name: 'test', renewal_threshold: 3, provider: provider_class.name)
      instance = provider_class.new(resource)
      instance.instance_variable_get(:@property_hash)[:expiration] = reference_time + (100 * 86_400)
      expect(instance.expires_soon_or_expired).to be false
    end

    it 'returns true if expiry time is in the near future' do
      resource = type_class.new(name: 'test', renewal_threshold: 3, provider: provider_class.name)
      instance = provider_class.new(resource)
      instance.instance_variable_get(:@property_hash)[:expiration] = reference_time + 86_400
      expect(instance.expires_soon_or_expired).to be true
    end

    it 'returns true if expiry time has already passed' do
      resource = type_class.new(name: 'test', renewal_threshold: 3, provider: provider_class.name)
      instance = provider_class.new(resource)
      instance.instance_variable_get(:@property_hash)[:expiration] = reference_time - 86_400
      expect(instance.expires_soon_or_expired).to be true
    end
  end

  describe 'needs_issue?' do
    let(:resource) do
      type_class.new({
                       name: '/etc/ssh/ssh_host_rsa_key.pub',
                       valid_principals: ['test.example.com'],
                       provider: provider_class.name
                     })
    end
    let(:instance) { provider_class.new(resource) }

    before :each do
      instance.instance_variable_get(:@property_hash)[:ensure] = :present
    end

    it "reissues if it doesn't already exist" do
      instance.instance_variable_get(:@property_hash)[:ensure] = :absent
      expect(instance).not_to receive(:expires_soon_or_expired)
      expect(instance.needs_issue?).to be true
    end

    it 'reissues if expires soon or already expired' do
      expect(instance).to receive(:expires_soon_or_expired).and_return(true)
      expect(instance.needs_issue?).to be true
    end

    it 'reissues if valid_principals are not in sync' do
      instance.instance_variable_get(:@property_flush)[:valid_principals] = []
      expect(instance).to receive(:expires_soon_or_expired).and_return(false)
      expect(instance.needs_issue?).to be true
    end

    it 'does not reissue if all conditions hold' do
      expect(instance).to receive(:expires_soon_or_expired).and_return(false)
      expect(instance.needs_issue?).to be false
    end
  end

  describe 'self.get_ca_trust' do
    before :each do
      allow(File).to receive(:exist?)
    end

    # '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    # '/etc/ssl/certs/ca-certificates.crt'

    it 'returns find the first certificate bundle when it exists' do
      expect(File).to receive(:exist?).with('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem').and_return(true)
      expect(provider_class.get_ca_trust).to eq '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    end

    it 'returns find the second certificate bundle when it exists' do
      expect(File).to receive(:exist?).with('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem').and_return(false)
      expect(File).to receive(:exist?).with('/etc/ssl/certs/ca-certificates.crt').and_return(true)
      expect(provider_class.get_ca_trust).to eq '/etc/ssl/certs/ca-certificates.crt'
    end

    it 'raises an error when neither certificate bundle exists' do
      expect(File).to receive(:exist?).with('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem').and_return(false)
      expect(File).to receive(:exist?).with('/etc/ssl/certs/ca-certificates.crt').and_return(false)
      expect {
        provider_class.get_ca_trust
      }.to raise_error(Puppet::Error, 'Failed to get the trusted CA certificate file')
    end
  end

  describe 'issue_cert' do
    context 'when given a valid URI' do
      let(:uri) { instance_double('URI::HTTP', hostname: 'vault.example.com', path: '/ssh/sign/cert') }

      before :each do
        expect(provider_class).to receive(:get_ca_trust).and_return('/test/ca.crt')
      end

      it 'obtains a new cert from vault' do
        resource = type_class.new({ name: '/testfile', vault_uri: 'http://vault.example.com/ssh/sign/cert', cert_type: 'host', timeout: 9,
  provider: provider_class.name })
        instance = provider_class.new(resource)
        vault_conn = instance_double('Vault')
        expect(VaultSession).to receive(:new).and_return(vault_conn)
        expect(instance).to receive(:URI).and_return(uri)
        expect(File).to receive(:read).with('/testfile').and_return('testkey')
        expect(vault_conn).to receive(:post).with('/ssh/sign/cert', { :cert_type => 'host', :public_key => 'testkey' }).and_return('response')
        expect(vault_conn).to receive(:parse_response).with('response').and_return('secrets')
        expect(instance.issue_cert).to eq 'secrets'
      end
    end
  end

  describe 'flush_attributes' do
    let(:instance) do
      resource = type_class.new({ name: 'test', file: '/testfile', provider: provider_class.name })
      provider_class.new(resource)
    end

    describe "when updating file" do
      it 'does nothing when all attributes are in sync' do
        expect(provider_class).not_to receive(:chown_file)
        expect(provider_class).not_to receive(:chmod_file)
        instance.flush_attributes(false)
      end

      it 'does nothing when change is signalled to owner but already in sync' do
        expect(provider_class).not_to receive(:chown_file)
        expect(provider_class).not_to receive(:chmod_file)
        instance.instance_variable_get(:@property_hash)[:owner] = 'testuser'
        instance.instance_variable_get(:@property_flush)[:owner] = 'testuser'
        instance.flush_attributes(false)
      end

      it 'does nothing when change is signalled to group but already in sync' do
        expect(provider_class).not_to receive(:chown_file)
        expect(provider_class).not_to receive(:chmod_file)
        instance.instance_variable_get(:@property_hash)[:group] = 'testgroup'
        instance.instance_variable_get(:@property_flush)[:group] = 'testgroup'
        instance.flush_attributes(false)
      end

      it 'does nothing when change is signalled to mode but already in sync' do
        expect(provider_class).not_to receive(:chown_file)
        expect(provider_class).not_to receive(:chmod_file)
        instance.instance_variable_get(:@property_hash)[:mode] = '0600'
        instance.instance_variable_get(:@property_flush)[:mode] = '0600'
        instance.flush_attributes(false)
      end

      it 'updates ownership when change is signalled to owner' do
        expect(provider_class).to receive(:chown_file).with('/testfile', 'testuser', nil)
        expect(provider_class).not_to receive(:chmod_file)
        instance.instance_variable_get(:@property_hash)[:owner] = 'otheruser'
        instance.instance_variable_get(:@property_flush)[:owner] = 'testuser'
        instance.flush_attributes(false)
      end

      it 'updates ownership when change is signalled to group' do
        expect(provider_class).to receive(:chown_file).with('/testfile', nil, 'testgroup')
        expect(provider_class).not_to receive(:chmod_file)
        instance.instance_variable_get(:@property_hash)[:group] = 'othergroup'
        instance.instance_variable_get(:@property_flush)[:group] = 'testgroup'
        instance.flush_attributes(false)
      end

      it 'updates permissions when change is signalled' do
        expect(provider_class).not_to receive(:chown_file)
        expect(provider_class).to receive(:chmod_file).with('/testfile', '0600')
        instance.instance_variable_get(:@property_hash)[:mode] = '0644'
        instance.instance_variable_get(:@property_flush)[:mode] = '0600'
        instance.flush_attributes(false)
      end

      it 'updates ownership and mode when change is forced' do
        expect(provider_class).to receive(:chown_file).with('/testfile', 'testuser', 'testgroup')
        expect(provider_class).to receive(:chmod_file).with('/testfile', '0600')
        instance.instance_variable_get(:@property_flush)[:owner] = 'testuser'
        instance.instance_variable_get(:@property_flush)[:group] = 'testgroup'
        instance.instance_variable_get(:@property_flush)[:mode] = '0600'
        instance.flush_attributes(true)
      end
    end
  end

  describe 'flush_file' do
    describe "when updating file" do
      let(:target) { '/testfile' }
      let(:resource) { type_class.new({ :name => 'test', :file => '/testfile', :owner => 'testuser', :group => 'testgroup', :mode => '0600', :provider => provider_class.name }) }
      let(:instance) { provider_class.new(resource) }

      it 'forces reset file attributes if the file path is being changed' do
        expect(File).to receive(:write).with('/testfile', 'testcontent')
        expect(instance).to receive(:flush_attributes).with(true)
        instance.instance_variable_get(:@property_hash)[:file] = '/test/vault-secrets/old-path.txt'
        instance.instance_variable_get(:@property_flush)[:file] = 'testfile'
        instance.flush_file('testcontent')
      end

      it 'deletes the original file if the path is being changed' do
        expect(File).to receive(:write).with('/testfile', 'testcontent')
        expect(provider_class).to receive(:delete_if_exists).with('/oldfile')
        expect(instance).to receive(:flush_attributes)
        instance.instance_variable_get(:@property_hash)[:file] = '/oldfile'
        instance.instance_variable_get(:@property_flush)[:file] = '/testfile'
        instance.flush_file('testcontent')
      end

      it 'updates the file if a change is signalled to the contents' do
        expect(provider_class).not_to receive(:delete_if_exists)
        expect(File).to receive(:write).with('/testfile', 'testcontent')
        expect(instance).to receive(:flush_attributes).with(true)
        instance.flush_file('testcontent')
      end
    end
  end

  describe 'flush' do
    let(:instance) do
      type_class.new({ name: '/testfile.pub',
                      file: '/testfile-cert.pub',
                      ensure: :present,
                      provider: provider_class.name })
      provider_class.new(resource)
    end

    it 'deletes the cert file if ensure is set to absent' do
      expect(provider_class).to receive(:delete_if_exists).with('/testfile-cert.pub')
      expect(File).not_to receive(:write)
      expect(instance).not_to receive(:flush_attributes)
      expect(instance).not_to receive(:flush_file)
      instance.instance_variable_get(:@property_flush)[:ensure] = :absent
      instance.flush
    end

    it 'does not delete cert file if ensure is set to present' do
      expect(provider_class).not_to receive(:delete_if_exists)
      expect(instance).to receive(:needs_issue?).and_return(false)
      expect(instance).to receive(:flush_attributes)
      allow(instance).to receive(:flush_file)
      instance.flush
    end

    it 'issues a new cert if needed and update all files' do
      expect(provider_class).not_to receive(:delete_if_exists)
      expect(instance).to receive(:needs_issue?).and_return(true)
      expect(instance).to receive(:issue_cert).and_return({ 'signed_key' => 'testcert' })
      expect(instance).to receive(:flush_file).with('testcert')
      instance.flush
    end

    it 'does not issue a new cert if not needed' do
      expect(instance).to receive(:needs_issue?).and_return(false)
      expect(provider_class).not_to receive(:delete_if_exists)
      expect(instance).not_to receive(:issue_cert)
      expect(File).not_to receive(:write)
      expect(instance).to receive(:flush_attributes)
      expect(instance).not_to receive(:flush_file)
      instance.flush
    end
  end
end
