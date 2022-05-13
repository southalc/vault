require 'json'
require 'spec_helper'

type_class = Puppet::Type.type(:vault_cert)
provider_class = type_class.provider(:vault_cert)

describe provider_class do
  let(:resource) do
    Puppet::Type.type(:vault_cert).new({ name: 'test', provider: described_class.name })
  end
  let(:provider) { resource.provider }

  before :each do
    allow(Facter).to receive(:value).with(:vault_cert_dir).and_return('/test/vault-secrets')
  end

  it 'has the correct vault_cert_dir' do
    resource = described_class.new(name: 'test', ensure: :present, cert_data: {}, expiration: 123)
    expect(resource.instance_variable_get(:@cert_dir)).to eq '/test/vault-secrets'
  end

  describe 'when loading existing instances' do
    before :each do
      info_files = {
        '/test/vault-secrets/test.json' => {
          contents: '{"data":{"expiration": 123, "ca_chain": ["testchain"], '\
                    '"issuing_ca": "testca", "certificate": "testcert", "private_key": "testkey"}, '\
                    '"cert_data": {}, "ca_chain_file": "/test/vault-secrets/test.chain.crt", '\
                    '"cert_file": "/test/vault-secrets/test.crt", "key_file": "/test/vault-secrets/test.key" }',
        },
        '/test/vault-secrets/test2.json' => {
          contents: '{"data":{"expiration": 123, "ca_chain": ["testchain2"], '\
                    '"issuing_ca": "testca2", "certificate": "testcert2", "private_key": "testkey2"}, '\
                    '"cert_data": {}, "ca_chain_file": "/test/vault-secrets/test2.chain.crt", '\
                    '"cert_file": "/test/vault-secrets/test2.crt", "key_file": "/test/vault-secrets/test2.key" }',
        }
      }

      allow(Dir).to receive(:glob).with('/test/vault-secrets/*.json').and_return(info_files.keys)
      info_files.each do |filename, details|
        info = JSON.parse(details[:contents])
        allow(provider_class).to receive(:load_file).with(filename).and_return([details[:contents], 'root', 'root', '0644'])
        allow(provider_class).to receive(:load_file).with(info['ca_chain_file']).and_return([info['data']['ca_chain'], 'root', 'root', '0644'])
        allow(provider_class).to receive(:load_file).with(info['cert_file']).and_return([info['data']['certificate'], 'root', 'root', '0644'])
        allow(provider_class).to receive(:load_file).with(info['key_file']).and_return([info['data']['private_key'], 'root', 'root', '0600'])
      end
    end

    describe 'self.instances' do
      it 'returns an aray of certificate data' do
        instances = provider_class.instances.map { |x| x.name }
        expect(instances).to contain_exactly('test', 'test2')
      end
    end

    describe 'self.prefetch' do
      it 'associates defined resources in the catalog with corresponding discovered instances on the system' do
        defined_resources = {
          'test1' => type_class.new(name: 'test1', provider: provider_class.name),
          'test2' => type_class.new(name: 'test2', provider: provider_class.name),
          'test3' => type_class.new(name: 'test3', provider: provider_class.name),
        }
        test1 = provider_class.new(name: 'test1', ensure: :present)
        test2 = provider_class.new(name: 'test2', ensure: :present)
        test4 = provider_class.new(name: 'test4', ensure: :present)
        allow(provider_class).to receive(:instances).and_return([
                                                                  test1, test2, test4
                                                                ])
        provider.class.prefetch(defined_resources)
        expect(defined_resources['test1'].provider).to be test1
        expect(defined_resources['test2'].provider).to be test2
        expect(defined_resources['test3'].provider).not_to be test4
      end
    end
  end

  describe 'self.load_file' do
    it 'returns nil when asked to load nil' do
      expect(File).not_to receive(:exist?)
      expect(File).not_to receive(:read)
      expect(File).not_to receive(:stat)

      expect(provider_class.load_file(nil)).to eq [nil, nil, nil, nil]
    end

    it 'returns nil when asked to load a non-existent file' do
      expect(File).to receive(:exist?).with('/test/vault-secrets/test.json').and_return(false)
      expect(File).not_to receive(:read)
      expect(File).not_to receive(:stat)

      expect(provider_class.load_file('/test/vault-secrets/test.json')).to eq [nil, nil, nil, nil]
    end

    it 'returns file attributes when called for an existing file' do
      file = '/test/vault-secrets/test.json'
      allow(File).to receive(:exist?).with(file).and_return(true)
      allow(File).to receive(:read).with(file).and_return('testcontent')
      allow(File::Stat).to receive(:new).with(file).and_return(instance_double('File::Stat', uid: 123, gid: 123, mode: 0o10644))
      allow(Etc).to receive(:getpwuid).with(123).and_return(instance_double('Passwd', name: 'testuser'))
      allow(Etc).to receive(:getgrgid).with(123).and_return(instance_double('Passwd', name: 'testgroup'))

      expect(provider_class.load_file(file)).to eq [
        'testcontent', 'testuser', 'testgroup', '0644'
      ]
    end
  end

  describe 'self.chown_file' do
    it 'does not do anything if both args are nil' do
      expect(File).not_to receive(:chown)
      provider_class.chown_file('/test/vault-secrets/test.json', nil, nil)
    end

    it 'changes file ownership and group when given user and group' do
      expect(Etc).to receive(:getpwnam).with('testuser').and_return(instance_double('Passwd', uid: 123))
      expect(Etc).to receive(:getgrnam).with('testgroup').and_return(instance_double('Passwd', gid: 123))
      expect(File).to receive(:chown).with(123, 123, '/test/vault-secrets/test.json')

      provider_class.chown_file('/test/vault-secrets/test.json', 'testuser', 'testgroup')
    end

    it 'changes file ownership when given user only' do
      expect(Etc).to receive(:getpwnam).with('testuser').and_return(instance_double('Passwd', uid: 123))
      expect(Etc).not_to receive(:getgrnam)
      expect(File).to receive(:chown).with(123, nil, '/test/vault-secrets/test.json')

      provider_class.chown_file('/test/vault-secrets/test.json', 'testuser', nil)
    end

    it 'changes file group when given group only' do
      expect(Etc).not_to receive(:getpwnam)
      expect(Etc).to receive(:getgrnam).with('testgroup').and_return(instance_double('Passwd', gid: 123))
      expect(File).to receive(:chown).with(nil, 123, '/test/vault-secrets/test.json')

      provider_class.chown_file('/test/vault-secrets/test.json', nil, 'testgroup')
    end
  end

  describe 'self.chmod_file' do
    it 'does not change file permissions if given nil' do
      expect(File).not_to receive(:chmod)
      provider_class.chmod_file('/test/vault-secrets/test.json', nil)
    end

    it 'changes the file permissions with the correct mode when given 0600' do
      expect(File).to receive(:chmod).with(0o600, '/test/vault-secrets/test.json')
      provider_class.chmod_file('/test/vault-secrets/test.json', '0600')
    end

    it 'changes the file permissions with the correct mode when given 0644' do
      expect(File).to receive(:chmod).with(0o644, '/test/vault-secrets/test.json')
      provider_class.chmod_file('/test/vault-secrets/test.json', '0644')
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
      expect(File).to receive(:exist?).with('/test/vault-secrets/test.json').and_return(false)
      expect(File).not_to receive(:delete)

      provider_class.delete_if_exists('/test/vault-secrets/test.json')
    end

    it 'deletes a valid existing file' do
      expect(File).to receive(:exist?).with('/test/vault-secrets/test.json').and_return(true)
      expect(File).to receive(:delete).with('/test/vault-secrets/test.json')

      provider_class.delete_if_exists('/test/vault-secrets/test.json')
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

  describe 'needs_reissue?' do
    let(:resource) do
      type_class.new({
                       name: 'test',
      provider: provider_class.name
                     })
    end
    let(:instance) { provider_class.new(resource) }

    before :each do
      instance.instance_variable_get(:@property_hash)[:ensure] = :present
      instance.instance_variable_get(:@property_hash)[:cert_data] = {
        'common_name': 'test.example.com',
      }
    end

    it "reissues if it doesn't already exist" do
      instance.instance_variable_get(:@property_hash)[:ensure] = :absent
      expect(instance).not_to receive(:expires_soon_or_expired)
      expect(instance.needs_issue?).to be true
    end

    it 'reissues if the cert_data has changed' do
      instance.cert_data = { 'common_name': 'test2.example.com' }
      expect(instance).not_to receive(:expires_soon_or_expired)
      expect(instance.needs_issue?).to be true
    end

    it 'does not reissue if the cert_data is flagged for change but has the same value' do
      instance.cert_data = { 'common_name': 'test.example.com' }
      expect(instance).to receive(:expires_soon_or_expired).and_return(false)
      expect(instance.needs_issue?).to be false
    end

    it 'reissues if expires soon or already expired' do
      expect(instance).to receive(:expires_soon_or_expired).and_return(true)
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
    context 'when given an invalid URI' do
      it 'raises an exception' do
        resource = type_class.new({ name: 'test', vault_uri: 'invalid', provider: provider_class.name })
        instance = provider_class.new(resource)
        expect(VaultSession).to receive(:new).and_raise(Puppet::Error, 'Unable to parse a hostname from invalid')
        # Vault.new should cause a failure before the path is calculated
        expect(instance).not_to receive(:URI)
        expect {
          instance.issue_cert
        }.to raise_error(Puppet::Error, %r{Unable to parse a hostname})
      end
    end

    context 'when given a valid URI' do
      let(:uri) { instance_double('URI::HTTP', hostname: 'vault.example.com', path: '/pki/issue/cert') }

      before :each do
        expect(provider_class).to receive(:get_ca_trust).and_return('/test/ca.crt')
      end

      it 'obtains a new cert from vault' do
        resource = type_class.new({ name: 'test', vault_uri: 'http://vault.example.com/pki/issue/cert', cert_data: { 'common_name': 'test.example.com' }, timeout: 9,
  provider: provider_class.name })
        instance = provider_class.new(resource)
        vault_conn = instance_double('Vault')
        expect(VaultSession).to receive(:new).and_return(vault_conn)
        expect(instance).to receive(:URI).and_return(uri)
        expect(vault_conn).to receive(:post).with('/pki/issue/cert', { 'common_name': 'test.example.com' }).and_return('response')
        expect(vault_conn).to receive(:parse_response).with('response').and_return('secrets')
        expect(instance.issue_cert).to eq 'secrets'
      end
    end
  end

  describe 'flush_file_attributes' do
    [
      ['info', '/test/vault-secrets/test.json', :info_owner, :info_group, :info_mode],
      ['ca_chain', '/test/vault-secrets/test.chain.crt', :ca_chain_owner, :ca_chain_group, :ca_chain_mode],
      ['cert', '/test/vault-secrets/test.crt', :cert_owner, :cert_group, :cert_mode],
      ['key', '/test/vault-secrets/test.key', :key_owner, :key_group, :key_mode],
    ].each do |file_attributes|
      file_name, path, owner, group, mode = file_attributes
      let(:instance) do
        resource = type_class.new({ name: 'test', provider: provider_class.name })
        provider_class.new(resource)
      end

      describe "when updating #{file_name} file" do
        it 'does nothing when all attributes are in sync' do
          expect(provider_class).not_to receive(:chown_file)
          expect(provider_class).not_to receive(:chmod_file)
          instance.flush_file_attributes(path, owner, group, mode, false)
        end

        it 'does nothing when change is signalled to owner but already in sync' do
          expect(provider_class).not_to receive(:chown_file)
          expect(provider_class).not_to receive(:chmod_file)
          instance.instance_variable_get(:@property_hash)[owner] = 'testuser'
          instance.instance_variable_get(:@property_flush)[owner] = 'testuser'
          instance.flush_file_attributes(path, owner, group, mode, false)
        end

        it 'does nothing when change is signalled to group but already in sync' do
          expect(provider_class).not_to receive(:chown_file)
          expect(provider_class).not_to receive(:chmod_file)
          instance.instance_variable_get(:@property_hash)[group] = 'testgroup'
          instance.instance_variable_get(:@property_flush)[group] = 'testgroup'
          instance.flush_file_attributes(path, owner, group, mode, false)
        end

        it 'does nothing when change is signalled to mode but already in sync' do
          expect(provider_class).not_to receive(:chown_file)
          expect(provider_class).not_to receive(:chmod_file)
          instance.instance_variable_get(:@property_hash)[mode] = '0600'
          instance.instance_variable_get(:@property_flush)[mode] = '0600'
          instance.flush_file_attributes(path, owner, group, mode, false)
        end

        it 'updates ownership when change is signalled to owner' do
          expect(provider_class).to receive(:chown_file).with(path, 'testuser', nil)
          expect(provider_class).not_to receive(:chmod_file)
          instance.instance_variable_get(:@property_hash)[owner] = 'otheruser'
          instance.instance_variable_get(:@property_flush)[owner] = 'testuser'
          instance.flush_file_attributes(path, owner, group, mode, false)
        end

        it 'updates ownership when change is signalled to group' do
          expect(provider_class).to receive(:chown_file).with(path, nil, 'testgroup')
          expect(provider_class).not_to receive(:chmod_file)
          instance.instance_variable_get(:@property_hash)[group] = 'othergroup'
          instance.instance_variable_get(:@property_flush)[group] = 'testgroup'
          instance.flush_file_attributes(path, owner, group, mode, false)
        end

        it 'updates permissions when change is signalled' do
          expect(provider_class).not_to receive(:chown_file)
          expect(provider_class).to receive(:chmod_file).with(path, '0600')
          instance.instance_variable_get(:@property_hash)[mode] = '0644'
          instance.instance_variable_get(:@property_flush)[mode] = '0600'
          instance.flush_file_attributes(path, owner, group, mode, false)
        end

        it 'updates ownership and mode when change is forced' do
          expect(provider_class).to receive(:chown_file).with(path, 'testuser', 'testgroup')
          expect(provider_class).to receive(:chmod_file).with(path, '0600')
          instance.instance_variable_get(:@property_flush)[owner] = 'testuser'
          instance.instance_variable_get(:@property_flush)[group] = 'testgroup'
          instance.instance_variable_get(:@property_flush)[mode] = '0600'
          instance.flush_file_attributes(path, owner, group, mode, true)
        end
      end
    end
  end

  describe 'flush_file' do
    [
      ['ca_chain', '/test/vault-secrets/test.chain.crt', :ca_chain_file, :ca_chain, :ca_chain_owner, :ca_chain_group, :ca_chain_mode],
      ['cert', '/test/vault-secrets/test.crt', :cert_file, :cert, :cert_owner, :cert_group, :cert_mode],
      ['key', '/test/vault-secrets/test.key', :key_file, :key, :key_owner, :key_group, :key_mode],
    ].each do |file_attributes|
      file_name, target, path, content, owner, group, mode = file_attributes

      describe "when updating #{file_name} file" do
        let(:info_file_target) { '/test/vault-secrets/test.json' }
        let(:resource) { type_class.new({ :name => 'test', path => target, owner => 'testuser', group => 'testgroup', mode => '0600', :provider => provider_class.name }) }
        let(:instance) { provider_class.new(resource) }

        before :each do
          # Derived property can't be set at object creation time due to validation
          # must be injected into the existing object, as would happen at runtime
          property_hash = instance.instance_variable_get(:@property_hash)
          property_hash[content] = 'testcontent'
          property_hash[path] = target
        end

        describe 'should force reset file attributes if the destination file did not previously exist' do
          it 'because content is not present in property hash' do
            expect(File).to receive(:write).with(target, 'testcontent')
            expect(instance).to receive(:flush_file_attributes).with(target, owner, group, mode, true)
            instance.instance_variable_get(:@property_hash).delete(content)
            instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            instance.flush_file(path, content, owner, group, mode)
          end

          it 'because content is present in property hash but is nil' do
            expect(File).to receive(:write).with(target, 'testcontent')
            expect(instance).to receive(:flush_file_attributes).with(target, owner, group, mode, true)
            instance.instance_variable_get(:@property_hash)[content] = nil
            instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            instance.flush_file(path, content, owner, group, mode)
          end

          it 'because content is present in the property hash but is blank' do
            expect(File).to receive(:write).with(target, 'testcontent')
            expect(instance).to receive(:flush_file_attributes).with(target, owner, group, mode, true)
            instance.instance_variable_get(:@property_hash)[content] = ''
            instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            instance.flush_file(path, content, owner, group, mode)
          end
        end

        it 'forces reset file attributes if the file path is being changed' do
          expect(File).to receive(:write).with(target, 'testcontent')
          expect(instance).to receive(:flush_file_attributes).with(target, owner, group, mode, true)
          instance.instance_variable_get(:@property_hash)[path] = '/test/vault-secrets/old-path.txt'
          instance.instance_variable_get(:@property_flush)[path] = target
          instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
          instance.flush_file(path, content, owner, group, mode)
        end

        it 'deletes the original file if the path is being changed' do
          expect(File).to receive(:write).with(target, 'testcontent')
          expect(provider_class).to receive(:delete_if_exists).with('/test/vault-secrets/old-path.txt')
          expect(instance).to receive(:flush_file_attributes)
          instance.instance_variable_get(:@property_hash)[path] = '/test/vault-secrets/old-path.txt'
          instance.instance_variable_get(:@property_flush)[path] = target
          instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
          instance.flush_file(path, content, owner, group, mode)
        end

        it 'updates the file if a change is signalled to the contents' do
          expect(provider_class).not_to receive(:delete_if_exists)
          expect(File).to receive(:write).with(target, 'testcontent')
          expect(instance).to receive(:flush_file_attributes).with(target, owner, group, mode, false)
          instance.instance_variable_get(:@property_hash)[content] = 'oldcontent'
          instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
          instance.flush_file(path, content, owner, group, mode)
        end

        it 'does not rewrite the file if a change of contents is signalled but is already in sync' do
          expect(provider_class).not_to receive(:delete_if_exists)
          expect(File).not_to receive(:write)
          expect(instance).to receive(:flush_file_attributes).with(target, owner, group, mode, false)
          instance.instance_variable_get(:@property_hash)[content] = 'testcontent'
          instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
          instance.flush_file(path, content, owner, group, mode)
        end
      end
    end
  end

  describe 'flush' do
    let(:instance) do
      type_class.new({ name: 'test',
                      ensure: :present,
                      ca_chain_file: '/test/vault-secrets/test.chain.crt',
                      cert_file: '/test/vault-secrets/test.crt',
                      key_file: '/test/vault-secrets/test.key',
                      provider: provider_class.name })
      provider_class.new(resource)
    end

    it 'deletes all files if ensure is set to absent' do
      expect(provider_class).to receive(:delete_if_exists).with('/test/vault-secrets/test.chain.crt')
      expect(provider_class).to receive(:delete_if_exists).with('/test/vault-secrets/test.crt')
      expect(provider_class).to receive(:delete_if_exists).with('/test/vault-secrets/test.key')
      expect(provider_class).to receive(:delete_if_exists).with('/test/vault-secrets/test.json')
      expect(File).not_to receive(:write)
      expect(instance).not_to receive(:flush_file_attributes)
      expect(instance).not_to receive(:flush_file)
      instance.instance_variable_get(:@property_flush)[:ensure] = :absent
      instance.flush
    end

    it 'does not delete any files if ensure is set to present' do
      expect(provider_class).not_to receive(:delete_if_exists)
      expect(instance).to receive(:needs_issue?).and_return(false)
      expect(File).to receive(:read).with('/test/vault-secrets/test.json').and_return('testdata')
      expect(JSON).to receive(:parse).with('testdata').and_return({ 'data' => { 'ca_chain' => ['testchain'], 'certificate' => 'testcert', 'private_key' => 'testkey' } })
      expect(instance).to receive(:flush_file_attributes)
      expect(instance).to receive(:flush_file).exactly(3).times
      instance.flush
    end

    it 'issues a new cert if needed and update all files' do
      expect(instance).to receive(:needs_issue?).and_return(true)
      expect(instance).to receive(:issue_cert).and_return({ 'ca_chain' => ['testchain'],
                                                          'issuing_ca' => 'testchain',
                                                          'certificate' => 'testcert',
                                                          'private_key' => 'testkey', })
      expect(JSON).to receive(:generate).and_return('testdata')
      expect(File).to receive(:write).with('/test/vault-secrets/test.json', 'testdata')
      expect(instance).to receive(:flush_file_attributes).with('/test/vault-secrets/test.json', :info_owner, :info_group, :info_mode, true)
      expect(instance).to receive(:flush_file).with(:ca_chain_file, :ca_chain, :ca_chain_owner, :ca_chain_group, :ca_chain_mode)
      expect(instance).to receive(:flush_file).with(:cert_file, :cert, :cert_owner, :cert_group, :cert_mode)
      expect(instance).to receive(:flush_file).with(:key_file, :key, :key_owner, :key_group, :key_mode)
      instance.flush
    end

    it 'does not issue a new cert if not needed' do
      expect(instance).to receive(:needs_issue?).and_return(false)
      expect(instance).not_to receive(:issue_cert)
      expect(File).not_to receive(:write)
      expect(JSON).to receive(:parse).with('testdata').and_return({ 'data' => { 'ca_chain' => ['testchain'], 'certificate' => 'testcert', 'private_key' => 'testkey' } })
      expect(File).to receive(:read).with('/test/vault-secrets/test.json').and_return('testdata')
      expect(instance).to receive(:flush_file_attributes).with('/test/vault-secrets/test.json', :info_owner, :info_group, :info_mode)
      expect(instance).to receive(:flush_file).with(:ca_chain_file, :ca_chain, :ca_chain_owner, :ca_chain_group, :ca_chain_mode)
      expect(instance).to receive(:flush_file).with(:cert_file, :cert, :cert_owner, :cert_group, :cert_mode)
      expect(instance).to receive(:flush_file).with(:key_file, :key, :key_owner, :key_group, :key_mode)
      instance.flush
    end
  end
end
