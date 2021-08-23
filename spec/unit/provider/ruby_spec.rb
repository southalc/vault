require 'json'
require 'spec_helper'

type_class = Puppet::Type.type(:vault_cert)
provider_class = type_class.provider(:ruby)

describe provider_class do
  let(:resource) {
    Puppet::Type.type(:vault_cert).new({ name: 'test', :provider => described_class.name})
  }
  let(:provider) { resource.provider }

  before :each do
    allow(Facter).to receive(:value).with(:vault_cert_dir).and_return('/test/vault-secrets')
  end

  it 'should have the correct vault_cert_dir' do
    resource = described_class.new(name: 'test', ensure: :present, cert_data: {}, expiration: 123)
    expect(resource.instance_variable_get(:@cert_dir)).to eq '/test/vault-secrets'
  end

  describe 'when loading existing instances' do
    before :each do
      info_files = {
        '/test/vault-secrets/test.json' => {
          :contents => '{"data":{"expiration": 123, "ca_chain": ["testchain"], "issuing_ca": "testca", "certificate": "testcert", "private_key": "testkey"}, "cert_data": {}, "ca_chain_file": "/test/vault-secrets/test.chain.crt", "cert_file": "/test/vault-secrets/test.crt", "key_file": "/test/vault-secrets/test.key" }',
        },
        '/test/vault-secrets/test2.json' => {
          :contents => '{"data":{"expiration": 123, "ca_chain": ["testchain2"], "issuing_ca": "testca2", "certificate": "testcert2", "private_key": "testkey2"}, "cert_data": {}, "ca_chain_file": "/test/vault-secrets/test2.chain.crt", "cert_file": "/test/vault-secrets/test2.crt", "key_file": "/test/vault-secrets/test2.key" }',
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
        instances = provider_class.instances.collect { |x| x.name }
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
    it 'should return nil when asked to load nil' do
      allow(File).to receive(:exists?)
      allow(File).to receive(:read)
      allow(File).to receive(:stat)

      expect(provider_class.load_file(nil)).to eq [nil, nil, nil, nil]

      expect(File).not_to have_received(:exists?)
      expect(File).not_to have_received(:read)
      expect(File).not_to have_received(:stat)
    end

    it 'should return nil when asked to load a non-existent file' do
      allow(File).to receive(:exists?).and_return(false)
      allow(File).to receive(:read)
      allow(File).to receive(:stat)

      expect(provider_class.load_file('/test/vault-secrets/test.json')).to eq [nil, nil, nil, nil]
      
      expect(File).to have_received(:exists?).with('/test/vault-secrets/test.json')
      expect(File).not_to have_received(:read)
      expect(File).not_to have_received(:stat)
    end

    it 'should return file attributes when called for an existing file' do
      file = '/test/vault-secrets/test.json'
      allow(File).to receive(:exists?).with(file).and_return(true)
      allow(File).to receive(:read).with(file).and_return('testcontent')
      allow(File::Stat).to receive(:new).with(file).and_return(double('File::Stat', :uid => 123, :gid => 123, :mode => 010644))
      allow(Etc).to receive(:getpwuid).with(123).and_return(double('Passwd', :name => 'testuser'))
      allow(Etc).to receive(:getgrgid).with(123).and_return(double('Passwd', :name => 'testgroup'))

      expect(provider_class.load_file(file)).to eq [
        'testcontent', 'testuser', 'testgroup', '0644'
      ]
    end
  end

  describe 'self.chown_file' do
    before :each do
      allow(File).to receive(:chown)
    end

    it 'should not do anything if both args are nil' do
      provider_class.chown_file('/test/vault-secrets/test.json', nil, nil)
      expect(File).not_to have_received(:chown)
    end

    it 'should change file ownership and group when given user and group' do
		  allow(Etc).to receive(:getpwnam).with('testuser').and_return(double('Passwd', :uid => 123))
		  allow(Etc).to receive(:getgrnam).with('testgroup').and_return(double('Passwd', :gid => 123))
      provider_class.chown_file('/test/vault-secrets/test.json', 'testuser', 'testgroup')
      expect(File).to have_received(:chown).with(123, 123, '/test/vault-secrets/test.json')
    end

    it 'should change file ownership when given user only' do
		  allow(Etc).to receive(:getpwnam).with('testuser').and_return(double('Passwd', :uid => 123))
		  allow(Etc).to receive(:getgrnam)
      provider_class.chown_file('/test/vault-secrets/test.json', 'testuser', nil)
      expect(File).to have_received(:chown).with(123, nil, '/test/vault-secrets/test.json')
      expect(Etc).not_to have_received(:getgrnam)
    end

    it 'should change file group when given group only' do
		  allow(Etc).to receive(:getpwnam)
      allow(Etc).to receive(:getgrnam).with('testgroup').and_return(double('Passwd', :gid => 123))
      provider_class.chown_file('/test/vault-secrets/test.json', nil, 'testgroup')
      expect(File).to have_received(:chown).with(nil, 123, '/test/vault-secrets/test.json')
      expect(Etc).not_to have_received(:getpwnam)
    end
  end
  
  describe 'self.chmod_file' do
    before :each do
      allow(File).to receive(:chmod)
    end

    it 'should not change file permissions if given nil' do
      provider_class.chmod_file('/test/vault-secrets/test.json', nil)
      expect(File).not_to have_received(:chmod)
    end

    it 'should change the file permissions with the correct mode when given 0600' do
      provider_class.chmod_file('/test/vault-secrets/test.json', '0600')
      expect(File).to have_received(:chmod).with(0600, '/test/vault-secrets/test.json')
    end

    it 'should change the file permissions with the correct mode when given 0644' do
      provider_class.chmod_file('/test/vault-secrets/test.json', '0644')
      expect(File).to have_received(:chmod).with(0644, '/test/vault-secrets/test.json')
    end
  end

  describe 'self.delete_if_exists' do
    before :each do
      allow(File).to receive(:delete)
    end 

    it 'should not delete file if given nil' do
      allow(File).to receive(:exist?)
      provider_class.delete_if_exists(nil)
      expect(File).not_to have_received(:exist?)
      expect(File).not_to have_received(:delete)
    end

    it 'should not delete file if given empty string' do
      allow(File).to receive(:exist?)
      provider_class.delete_if_exists('')
      expect(File).not_to have_received(:exist?)
      expect(File).not_to have_received(:delete)
    end

    it 'should not try to delete file if if it doesn\'t exist' do
      allow(File).to receive(:exist?).and_return(false)
      provider_class.delete_if_exists('/test/vault-secrets/test.json')
      expect(File).to have_received(:exist?).with('/test/vault-secrets/test.json')
      expect(File).not_to have_received(:delete)
    end
 
    it 'should delete a valid existing file' do
      allow(File).to receive(:exist?).with('/test/vault-secrets/test.json').and_return(true)
      provider_class.delete_if_exists('/test/vault-secrets/test.json')
      expect(File).to have_received(:exist?).with('/test/vault-secrets/test.json')
      expect(File).to have_received(:delete).with('/test/vault-secrets/test.json')
    end
  end

  describe 'expires_soon_or_expired' do
    before :each do
      @reference_time = 1609459200  # Midnight 1st Jan 2021
      allow(Time).to receive(:now).and_return(double('Time', :to_i => @reference_time))
    end

    it 'should return false if expiry time is far in the future' do
      resource = type_class.new(name: 'test', :renewal_threshold => 3, :provider => provider_class.name)
      instance = provider_class.new(resource)
      instance.instance_variable_get(:@property_hash)[:expiration] = @reference_time + (100 * 86400)
      expect(instance.expires_soon_or_expired).to be false
    end

    it 'should return true if expiry time is in the near future' do
      resource = type_class.new(name: 'test', :renewal_threshold => 3, :provider => provider_class.name)
      instance = provider_class.new(resource)
      instance.instance_variable_get(:@property_hash)[:expiration] = @reference_time + 86400
      expect(instance.expires_soon_or_expired).to be true
    end

    it 'should return true if expiry time has already passed' do
      resource = type_class.new(name: 'test', :renewal_threshold => 3, :provider => provider_class.name)
      instance = provider_class.new(resource)
      instance.instance_variable_get(:@property_hash)[:expiration] = @reference_time - 86400
      expect(instance.expires_soon_or_expired).to be true
    end
  end

  describe 'needs_reissue?' do
    before :each do
      @instance = provider_class.new(name: 'test', :ensure => :present, :cert_data => {
        'common_name': 'test.example.com',
      })
      allow(@instance).to receive(:expires_soon_or_expired).and_return(false)
    end

    it 'should reissue if it doesn\'t already exist' do
      @instance.instance_variable_get(:@property_hash)[:ensure] = :absent
      expect(@instance.needs_issue?). to be true
    end

    it 'should reissue if the cert_data has changed' do
      @instance.cert_data = {'common_name': 'test2.example.com'}
      expect(@instance.needs_issue?). to be true
    end

    it 'should not reissue if the cert_data is flagged for change but has the same value' do
      @instance.cert_data = {'common_name': 'test.example.com'}
      expect(@instance.needs_issue?). to be false
    end

    it 'should reissue if expires soon or already expired' do
      allow(@instance).to receive(:expires_soon_or_expired).and_return(true)
      expect(@instance.needs_issue?). to be true
    end

    it 'should not reissue if all conditions hold' do
      expect(@instance.needs_issue?). to be false
    end
  end

  describe 'self.get_ca_trust' do
    before :each do
      allow(File).to receive(:exist?)
    end

		#'/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
		#'/etc/ssl/certs/ca-certificates.crt'

    it 'should return find the first certificate bundle when it exists' do
      allow(File).to receive(:exist?).with('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem').and_return(true)
      expect(provider_class.get_ca_trust).to eq '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    end

    it 'should return find the second certificate bundle when it exists' do
      allow(File).to receive(:exist?).with('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem').and_return(false)
      allow(File).to receive(:exist?).with('/etc/ssl/certs/ca-certificates.crt').and_return(true)
      expect(provider_class.get_ca_trust).to eq '/etc/ssl/certs/ca-certificates.crt'
    end

    it 'should raise an error when neither certificate bundle exists' do
      allow(File).to receive(:exist?).with('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem').and_return(false)
      allow(File).to receive(:exist?).with('/etc/ssl/certs/ca-certificates.crt').and_return(false)
      expect do
        provider_class.get_ca_trust
      end.to raise_error(Puppet::Error, 'Failed to get the trusted CA certificate file')
    end
  end

  describe 'issue_cert' do
		#http = http_create_secure(uri, ca_trust, @resource[:timeout])
		#token = vault_get_token(http, @resource[:auth_path].delete('/'))
		#secrets = vault_http_post(http, uri.path, token, @resource[:cert_data])
		#response = vault_parse_data(secrets)

    before :each do
      allow(provider_class).to receive(:get_ca_trust).and_return('/test/ca.crt')
      allow_any_instance_of(provider_class).to receive(:http_create_secure).and_return(1)
      allow_any_instance_of(provider_class).to receive(:vault_get_token).and_return('secrettoken')
      allow_any_instance_of(provider_class).to receive(:vault_http_post).and_return('secrets')
      allow_any_instance_of(provider_class).to receive(:vault_parse_data).with('secrets').and_return('secrets')
    end

    it 'should raise an exception when given an invalid URI' do
      allow(URI).to receive(:new).and_return(double('URI::HTTP', :hostname => nil))
      resource = type_class.new({:name => 'test', :vault_uri => 'invalid', :provider => provider_class.name})
      instance = provider_class.new(resource)
      expect do
        instance.issue_cert
      end.to raise_error(Puppet::Error, /Unable to parse a hostname/)
    end

    it 'should obtain a new cert from vault when given a valid URI' do
      allow(URI).to receive(:new).and_return(double('URI::HTTP', :hostname => 'vault.example.com', :path => '/'))
      resource = type_class.new({:name => 'test', :vault_uri => 'http://vault.example.com/pki/issue/cert', :cert_data => {'common_name': 'test.example.com'}, :timeout => 9, :provider => provider_class.name})
      instance = provider_class.new(resource)
      expect(instance.issue_cert).to eq 'secrets'
      expect(instance).to have_received(:http_create_secure).with(URI('http://vault.example.com/pki/issue/cert'), '/test/ca.crt', 9)
      expect(instance).to have_received(:vault_get_token).with(1, 'puppet-pki')
      expect(instance).to have_received(:vault_http_post).with(1, '/pki/issue/cert', 'secrettoken', {'common_name': 'test.example.com'})
      expect(instance).to have_received(:vault_parse_data).with('secrets')
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

      describe "when updating #{file_name} file" do
        before :each do
          @resource = type_class.new({:name => 'test', :provider => provider_class.name})
          @instance = provider_class.new(@resource)
          allow(provider_class).to receive(:chown_file)
          allow(provider_class).to receive(:chmod_file)
        end

        it 'should do nothing when all attributes are in sync' do
          @instance.flush_file_attributes(path, owner, group, mode, false)
          expect(provider_class).not_to have_received(:chown_file)
          expect(provider_class).not_to have_received(:chmod_file)
        end

        it 'should do nothing when change is signalled to owner but already in sync' do
          @instance.instance_variable_get(:@property_hash)[owner] = 'testuser'
          @instance.instance_variable_get(:@property_flush)[owner] = 'testuser'
          @instance.flush_file_attributes(path, owner, group, mode, false)
          expect(provider_class).not_to have_received(:chown_file)
          expect(provider_class).not_to have_received(:chmod_file)
        end

        it 'should do nothing when change is signalled to group but already in sync' do
          @instance.instance_variable_get(:@property_hash)[group] = 'testgroup'
          @instance.instance_variable_get(:@property_flush)[group] = 'testgroup'
          @instance.flush_file_attributes(path, owner, group, mode, false)
          expect(provider_class).not_to have_received(:chown_file)
          expect(provider_class).not_to have_received(:chmod_file)
        end

        it 'should do nothing when change is signalled to mode but already in sync' do
          @instance.instance_variable_get(:@property_hash)[mode] = '0600'
          @instance.instance_variable_get(:@property_flush)[mode] = '0600'
          @instance.flush_file_attributes(path, owner, group, mode, false)
          expect(provider_class).not_to have_received(:chown_file)
          expect(provider_class).not_to have_received(:chmod_file)
        end

        it 'should update ownership when change is signalled to owner' do
          @instance.instance_variable_get(:@property_hash)[owner] = 'otheruser'
          @instance.instance_variable_get(:@property_flush)[owner] = 'testuser'
          @instance.flush_file_attributes(path, owner, group, mode, false)
          expect(provider_class).to have_received(:chown_file).with(path, 'testuser', nil)
          expect(provider_class).not_to have_received(:chmod_file)
        end

        it 'should update ownership when change is signalled to group' do
          @instance.instance_variable_get(:@property_hash)[group] = 'othergroup'
          @instance.instance_variable_get(:@property_flush)[group] = 'testgroup'
          @instance.flush_file_attributes(path, owner, group, mode, false)
          expect(provider_class).to have_received(:chown_file).with(path, nil, 'testgroup')
          expect(provider_class).not_to have_received(:chmod_file)
        end

        it 'should update permissions when change is signalled' do
          @instance.instance_variable_get(:@property_hash)[mode] = '0644'
          @instance.instance_variable_get(:@property_flush)[mode] = '0600'
          @instance.flush_file_attributes(path, owner, group, mode, false)
          expect(provider_class).not_to have_received(:chown_file)
          expect(provider_class).to have_received(:chmod_file).with(path, '0600')
        end

        it 'should update ownership and mode when change is forced' do
          @instance.instance_variable_get(:@property_flush)[owner] = 'testuser'
          @instance.instance_variable_get(:@property_flush)[group] = 'testgroup'
          @instance.instance_variable_get(:@property_flush)[mode] = '0600'
          @instance.flush_file_attributes(path, owner, group, mode, true)
          expect(provider_class).to have_received(:chown_file).with(path, 'testuser', 'testgroup')
          expect(provider_class).to have_received(:chmod_file).with(path, '0600')
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

        before :each do
          allow(File).to receive(:write)
          @info_file_target = '/test/vault-secrets/test.json'
          @resource = type_class.new({:name => 'test', path => target, owner => 'testuser', group => 'testgroup', mode => '0600', :provider => provider_class.name})
          @instance = provider_class.new(@resource)
          # Derived property can't be set at object creation time due to validation
          # must be injected into the existing object, as would happen at runtime
          property_hash = @instance.instance_variable_get(:@property_hash)
          property_hash[content] = 'testcontent'
          property_hash[path] = target
          allow(provider_class).to receive(:delete_if_exists)
          allow(@instance).to receive(:flush_file_attributes)
        end

        describe 'should force reset file attributes if the destination file did not previously exist' do
          it 'because content is not present in property hash' do
            @instance.instance_variable_get(:@property_hash).delete(content)
            @instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            @instance.flush_file(path, content, owner, group, mode)
            expect(File).to have_received(:write).with(target, 'testcontent')
            expect(@instance).to have_received(:flush_file_attributes).with(target, owner, group, mode, true)
          end

          it 'because content is present in property hash but is nil' do
            @instance.instance_variable_get(:@property_hash)[content] = nil
            @instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            @instance.flush_file(path, content, owner, group, mode)
            expect(File).to have_received(:write).with(target, 'testcontent')
            expect(@instance).to have_received(:flush_file_attributes).with(target, owner, group, mode, true)
          end

          it 'because content is present in the property hash but is blank' do
            @instance.instance_variable_get(:@property_hash)[content] = ''
            @instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            @instance.flush_file(path, content, owner, group, mode)
            expect(File).to have_received(:write).with(target, 'testcontent')
            expect(@instance).to have_received(:flush_file_attributes).with(target, owner, group, mode, true)
          end
        end
        
        it 'should force reset file attributes if the file path is being changed' do
            @instance.instance_variable_get(:@property_hash)[path] = '/test/vault-secrets/old-path.txt'
            @instance.instance_variable_get(:@property_flush)[path] = target
            @instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            @instance.flush_file(path, content, owner, group, mode)
            expect(File).to have_received(:write).with(target, 'testcontent')
            expect(@instance).to have_received(:flush_file_attributes).with(target, owner, group, mode, true)
        end

        it 'should delete the original file if the path is being changed' do
            @instance.instance_variable_get(:@property_hash)[path] = '/test/vault-secrets/old-path.txt'
            @instance.instance_variable_get(:@property_flush)[path] = target
            @instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            @instance.flush_file(path, content, owner, group, mode)
            expect(provider_class).to have_received(:delete_if_exists).with('/test/vault-secrets/old-path.txt')
        end

        it 'should update the file if a change is signalled to the contents' do
            @instance.instance_variable_get(:@property_hash)[content] = 'oldcontent'
            @instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            @instance.flush_file(path, content, owner, group, mode)
            expect(provider_class).not_to have_received(:delete_if_exists)
            expect(File).to have_received(:write).with(target, 'testcontent')
            expect(@instance).to have_received(:flush_file_attributes).with(target, owner, group, mode, false)
        end

        it 'should not rewrite the file if a change of contents is signalled but is already in sync' do
            @instance.instance_variable_get(:@property_hash)[content] = 'testcontent'
            @instance.instance_variable_get(:@property_flush)[content] = 'testcontent'
            @instance.flush_file(path, content, owner, group, mode)
            expect(provider_class).not_to have_received(:delete_if_exists)
            expect(File).not_to have_received(:write)
            expect(@instance).to have_received(:flush_file_attributes).with(target, owner, group, mode, false)
        end
      end
    end
  end

  describe 'flush' do
    before :each do
      @resource = type_class.new({
        :name => 'test',
        :ensure => :present,
        :ca_chain_file => '/test/vault-secrets/test.chain.crt',
        :cert_file => '/test/vault-secrets/test.crt',
        :key_file => '/test/vault-secrets/test.key',
        :provider => provider_class.name})
      @instance = provider_class.new(@resource)
      allow(provider_class).to receive(:delete_if_exists)
      allow(@instance).to receive(:flush_file_attributes)
      allow(@instance).to receive(:flush_file)
      allow(@instance).to receive(:needs_issue?).and_return(false)
      allow(@instance).to receive(:issue_cert).and_return({
        'ca_chain' => ['testchain'],
        'issuing_ca' => 'testchain',
        'certificate' => 'testcert',
        'private_key' => 'testkey',
      })
      allow(JSON).to receive(:generate).and_return('testdata')
      allow(JSON).to receive(:parse).and_return({'data' => { 'ca_chain' => ['testchain'], 'certificate' => 'testcert', 'private_key' => 'testkey'}})
      allow(File).to receive(:read).and_return('testdata')
      allow(File).to receive(:write)
    end

    it 'should delete all files if ensure is set to absent' do
      @instance.instance_variable_get(:@property_flush)[:ensure] = :absent
      @instance.flush
      expect(provider_class).to have_received(:delete_if_exists).with('/test/vault-secrets/test.chain.crt')
      expect(provider_class).to have_received(:delete_if_exists).with('/test/vault-secrets/test.crt')
      expect(provider_class).to have_received(:delete_if_exists).with('/test/vault-secrets/test.key')
      expect(provider_class).to have_received(:delete_if_exists).with('/test/vault-secrets/test.json')
    end
    
    it 'should not delete any files if ensure is not set to absent' do
      @instance.flush
      expect(provider_class).not_to have_received(:delete_if_exists)
    end

    it 'should issue a new cert if needed and update all files' do
      allow(@instance).to receive(:needs_issue?).and_return(true)
      @instance.flush
      expect(@instance).to have_received(:issue_cert)
      expect(JSON).to have_received(:generate)
      expect(File).to have_received(:write).with('/test/vault-secrets/test.json', 'testdata')
      expect(@instance).to have_received(:flush_file_attributes).with('/test/vault-secrets/test.json', :info_owner, :info_group, :info_mode, true)
      expect(@instance).to have_received(:flush_file).with(:ca_chain_file, :ca_chain, :ca_chain_owner, :ca_chain_group, :ca_chain_mode)
      expect(@instance).to have_received(:flush_file).with(:cert_file, :cert, :cert_owner, :cert_group, :cert_mode)
      expect(@instance).to have_received(:flush_file).with(:key_file, :key, :key_owner, :key_group, :key_mode)
    end

    it 'should not issue a new cert if not needed' do
      @instance.flush
      expect(@instance).not_to have_received(:issue_cert)
      expect(File).not_to have_received(:write)
      expect(File).to have_received(:read).with('/test/vault-secrets/test.json')
      expect(JSON).to have_received(:parse).with('testdata')
      expect(@instance).to have_received(:flush_file_attributes).with('/test/vault-secrets/test.json', :info_owner, :info_group, :info_mode)
      expect(@instance).to have_received(:flush_file).with(:ca_chain_file, :ca_chain, :ca_chain_owner, :ca_chain_group, :ca_chain_mode)
      expect(@instance).to have_received(:flush_file).with(:cert_file, :cert, :cert_owner, :cert_group, :cert_mode)
      expect(@instance).to have_received(:flush_file).with(:key_file, :key, :key_owner, :key_group, :key_mode)
    end
  end
end