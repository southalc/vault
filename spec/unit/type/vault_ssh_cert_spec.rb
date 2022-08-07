require 'spec_helper'

describe Puppet::Type.type(:vault_ssh_cert) do
  it 'is an instance of Puppet::Type::Vault_ssh_cert' do
    expect(described_class.new(name: 'test')).to be_an_instance_of Puppet::Type::Vault_ssh_cert
  end

  describe 'when validating attributes' do
    params = [:name, :vault_uri, :auth_path, :auth_name, :ttl, :cert_type, :timeout, :renewal_threshold]
    properties = [:file, :owner, :group, :mode, :expiration, :valid_principals]

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
    read_only_properties = [:expiration].freeze

    read_only_properties.each do |prop|
      context prop.to_s do
        it 'passes using default auto' do
          expect {
            described_class.new(name: 'test', vault_uri: '')
          }.not_to raise_error
        end

        it 'passes using explicit auto' do
          expect {
            params = { prop => :auto }
            described_class.new(name: 'test', vault_uri: '', **params)
          }.not_to raise_error
        end

        it 'fails using non-auto value' do
          expect {
            params = { prop => 'foobar' }
            described_class.new(name: 'test', vault_uri: '', **params)
          }.to raise_error Puppet::Error, %r{Invalid value "foobar"}
        end
      end
    end
  end

  describe 'when validating certificate expiration' do
    let(:cls) { described_class }
    let(:provider_class) { cls.provide(:fake) { mk_resource_methods } }
    let(:provider) { provider_class.new }
    let(:resource) { described_class.new(name: 'test', vault_uri: '', provider: provider) }

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

  describe 'when validating valid_principals' do
    let(:provider_class) { described_class.provide(:fake) { mk_resource_methods } }
    let(:provider) { provider_class.new }

    it 'fails validation when not all entries are Strings' do
      expect {
        described_class.new(name: 'test', vault_uri: '', valid_principals: [1], provider: provider)
      }.to raise_error Puppet::Error, %r{All valid_principals values must be Strings}
    end

    it 'passes validation when given a list of names' do
      expect {
        described_class.new(name: 'test', vault_uri: '', valid_principals: ['one', 'two.three'], provider: provider)
      }.not_to raise_error
    end
  end

  describe 'when validating file autorequires' do
    let(:file_resource) { Puppet::Type.type(:file).new(path: '/test/ssh_host_test-cert.pub') }
    let(:catalog) { Puppet::Resource::Catalog.new }

    context 'using the default property values' do
      let(:cert_resource) { described_class.new({ name: '/test/ssh_host_test.pub' }) }
      let(:auto_req) { cert_resource.autorequire }

      before :each do
        catalog.add_resource file_resource
        catalog.add_resource cert_resource
      end

      it 'contains exactly one file autorequire' do
        expect(auto_req.size).to eq 1
      end

      it 'links to the info file' do
        expect(auto_req.map { |rp| rp.source.to_s }).to include('File[/test/ssh_host_test-cert.pub]')
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
