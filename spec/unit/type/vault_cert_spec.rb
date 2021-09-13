require 'spec_helper'

describe Puppet::Type.type(:vault_cert) do
  it 'is an instance of Puppet::Type::Vault_cert' do
    expect(described_class.new(name: 'test')).to be_an_instance_of Puppet::Type::Vault_cert
  end

  describe 'when validating attributes' do
    params = [:name, :vault_uri, :auth_path, :timeout, :renewal_threshold]
    properties = [
      :cert_data,
      :info_owner, :info_group, :info_mode,
      :ca_chain_file, :ca_chain_owner, :ca_chain_group, :ca_chain_mode, :ca_chain, :info_ca_chain,
      :cert_file, :cert_owner, :cert_group, :cert_mode, :cert, :info_cert,
      :key_file, :key_owner, :key_group, :key_mode, :key, :info_key,
      :expiration
    ]

    params.each do |param|
      it "has the #{param} param" do
        expect(described_class.attrtype(param)).to eq :param
      end
    end

    properties.each do |property|
      it "has the #{property} property" do
        expect(described_class.attrtype(property)).to eq :property
      end
    end
  end

  it 'has name as the namevar' do
    expect(described_class.key_attributes).to eq [:name]
  end

  describe 'when validating read-only property' do
    read_only_properties = [
      :ca_chain, :cert, :key, :expiration,
      :info_ca_chain, :info_cert, :info_key
    ].freeze

    read_only_properties.each do |prop|
      context prop.to_s do
        it 'passes using default auto' do
          expect {
            described_class.new(name: 'test', vault_uri: '', cert_data: {})
          }.not_to raise_error
        end

        it 'passes using explicit auto' do
          expect {
            params = { prop => :auto }
            described_class.new(name: 'test', vault_uri: '', cert_data: {}, **params)
          }.not_to raise_error
        end

        it 'fails using non-auto value' do
          expect {
            params = { prop => 'foobar' }
            described_class.new(name: 'test', vault_uri: '', cert_data: {}, **params)
          }.to raise_error Puppet::Error, %r{Invalid value "foobar"}
        end
      end
    end
  end

  describe 'when validating insync? on read-only properties' do
    properties = [
      :info_ca_chain, :info_cert, :info_key
    ].freeze

    properties.each do |prop|
      context prop.to_s do
        it 'is insync always' do
          resource = described_class.new(name: 'test', vault_uri: '', cert_data: {})
          expect(resource.property(prop).insync?(:auto)).to be true
        end
      end
    end
  end

  describe 'when validating insync? on derived properties' do
    properties = [
      [:ca_chain, :info_ca_chain],
      [:cert, :info_cert],
      [:key, :info_key],
    ].freeze

    let(:cls) { described_class }
    let(:provider_class) { cls.provide(:fake) { mk_resource_methods } }
    let(:provider) { provider_class.new }

    before :each do
      allow(cls).to receive(:defaultprovider).and_return(provider_class)
      properties.each do |prop|
        allow(provider).to receive(prop[1]).and_return('foobar')
      end
    end

    properties.each do |prop|
      context prop[0].to_s do
        it "is insync when #{prop[0]} matches #{prop[1]}" do
          resource = described_class.new(name: 'test', vault_uri: '', cert_data: {}, provider: provider)
          expect(resource.property(prop[0]).insync?('foobar')).to be true
        end

        it "is not insync when #{prop[0]} does not match #{prop[1]}" do
          resource = described_class.new(name: 'test', vault_uri: '', cert_data: {}, provider: provider)
          expect(resource.property(prop[0]).insync?('notfoobar')).to be false
        end
      end
    end
  end

  describe 'when validating certificate expiration' do
    let(:cls) { described_class }
    let(:provider_class) { cls.provide(:fake) { mk_resource_methods } }
    let(:provider) { provider_class.new }
    let(:resource) { described_class.new(name: 'test', vault_uri: '', cert_data: {}, provider: provider) }

    before :each do
      allow(cls).to receive(:defaultprovider).and_return(provider_class)
    end

    context 'which is not expiring or expired' do
      it 'is in sync' do
        allow(provider).to receive(:expires_soon_or_expired).and_return(false)
        expect(resource.property(:expiration).insync?('unused')).to be true
      end
    end

    context 'which is expiring or expired' do
      it 'is not in sync' do
        allow(provider).to receive(:expires_soon_or_expired).and_return(true)
        expect(resource.property(:expiration).insync?('unused')).to be false
      end
    end
  end

  describe 'when validating file autorequires' do
    let(:pki_file_resource) { Puppet::Type.type(:file).new(path: '/test/vault-secrets') }
    let(:app_file_resource) { Puppet::Type.type(:file).new(path: '/test/app') }
    let(:catalog) { Puppet::Resource::Catalog.new }

    before :each do
      allow(Facter).to receive(:value)
      allow(Facter).to receive(:value).with(:vault_cert_dir).and_return('/test/vault-secrets')
    end

    context 'using the default property values' do
      let(:cert_resource) { described_class.new({ name: 'test' }) }
      let(:auto_req) { cert_resource.autorequire }

      before :each do
        catalog.add_resource pki_file_resource
        catalog.add_resource cert_resource
      end

      it 'contains exactly one file autorequire' do
        expect(auto_req.size).to eq 1
      end

      it 'links to the info file directory' do
        expect(auto_req.map { |rp| rp.source.to_s }).to include('File[/test/vault-secrets]')
      end
    end

    context 'using an app dir for chain/cert/key files' do
      let(:cert_resource) { described_class.new({ name: 'test', ca_chain_file: '/test/app/testchain.crt', cert_file: '/test/app/test.crt', key_file: '/test/app/test.key' }) }
      let(:auto_req) { cert_resource.autorequire }

      before :each do
        catalog.add_resource pki_file_resource
        catalog.add_resource app_file_resource
        catalog.add_resource cert_resource
      end

      it 'contains exactly two file autorequire' do
        expect(auto_req.size).to eq 2
      end

      it 'links to the info file directory and the app directory' do
        requires = auto_req.map { |rp| rp.source.to_s }
        expect(requires).to include('File[/test/vault-secrets]')
        expect(requires).to include('File[/test/app]')
      end
    end
  end

  describe 'when validating user autorequires' do
    let(:user_resource) { Puppet::Type.type(:user).new(name: 'root') }
    let(:catalog) { Puppet::Resource::Catalog.new }

    context 'using the default property values' do
      let(:cert_resource) { described_class.new({ name: 'test' }) }
      let(:auto_req) { cert_resource.autorequire }

      before :each do
        catalog.add_resource user_resource
        catalog.add_resource cert_resource
      end

      it 'contains exactly one user autorequire' do
        expect(auto_req.size).to eq 1
      end

      it 'links to the user resource' do
        expect(auto_req.map { |rp| rp.source.to_s }).to include('User[root]')
      end
    end
  end

  describe 'when validating group autorequires' do
    let(:group_resource) { Puppet::Type.type(:group).new(name: 'root') }
    let(:catalog) { Puppet::Resource::Catalog.new }

    context 'using the default property values' do
      let(:cert_resource) { described_class.new({ name: 'test' }) }
      let(:auto_req) { cert_resource.autorequire }

      before :each do
        catalog.add_resource group_resource
        catalog.add_resource cert_resource
      end

      it 'contains exactly one group autorequire' do
        expect(auto_req.size).to eq 1
      end

      it 'links to the group resource' do
        expect(auto_req.map { |rp| rp.source.to_s }).to include('Group[root]')
      end
    end
  end
end
