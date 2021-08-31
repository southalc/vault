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
      :expiration,
    ]

    params.each do |param|
      it "should have the #{param} param" do
        expect(described_class.attrtype(param)).to eq :param
      end
    end

    properties.each do |property|
      it "should have the #{property} property" do
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
      :info_ca_chain, :info_cert, :info_key,
    ].freeze

    read_only_properties.each do |prop|
      context prop.to_s do
        it 'passes using default auto' do
          expect do
            described_class.new(name: 'test', vault_uri: '', cert_data: {})
          end.not_to raise_error
        end

        it 'passes using explicit auto' do
          expect do
            params = {prop => :auto}
            described_class.new(name: 'test', vault_uri: '', cert_data: {}, **params)
          end.not_to raise_error
        end

        it 'fails using non-auto value' do
          expect do
            params = {prop => "foobar"}
            described_class.new(name: 'test', vault_uri: '', cert_data: {}, **params)
          end.to raise_error Puppet::Error, %r{Invalid value "foobar"}
        end
      end
    end
  end

  describe 'when validating insync? on read-only properties' do
    properties = [
      :info_ca_chain, :info_cert, :info_key,
    ].freeze

    properties.each do |prop|
      context prop.to_s do

        it "is insync always" do
          resource = described_class.new(name: 'test', vault_uri: '', cert_data: {})
          expect(resource.property(prop).insync? :auto).to be true
        end
      end
    end
  end

  describe "when validating insync? on derived properties" do
    properties = [
      [:ca_chain, :info_ca_chain],
      [:cert, :info_cert],
      [:key, :info_key],
    ].freeze

    before :each do
      @class = described_class
      @provider_class = @class.provide(:fake) { mk_resource_methods }
      @provider = @provider_class.new
      allow(@class).to receive(:defaultprovider).and_return(@provider_class)
      properties.each do |prop|
        allow(@provider).to receive(prop[1]).and_return('foobar')
      end
    end

    properties.each do |prop|
      context prop[0].to_s do

        it "is insync when #{prop[0]} matches #{prop[1]}" do
          resource = described_class.new(name: 'test', vault_uri: '', cert_data: {}, provider: @provider)
          expect(resource.property(prop[0]).insync? 'foobar').to be true
        end

        it "is not insync when #{prop[0]} does not match #{prop[1]}" do
          resource = described_class.new(name: 'test', vault_uri: '', cert_data: {}, provider: @provider)
          expect(resource.property(prop[0]).insync? 'notfoobar').to be false
        end
      end
    end
  end

  describe 'when validating certificate expiration' do
    before :each do
      @class = described_class
      @provider_class = @class.provide(:fake) { mk_resource_methods }
      @provider = @provider_class.new
      allow(@class).to receive(:defaultprovider).and_return(@provider_class)
      @resource = described_class.new(name: 'test', vault_uri: '', cert_data: {}, provider: @provider)
    end

    context 'which is not expiring or expired' do
      it 'should be in sync' do
        allow(@provider).to receive(:expires_soon_or_expired).and_return(false)
        expect(@resource.property(:expiration).insync? 'unused').to be true
      end
    end

    context 'which is expiring or expired' do
      it 'should not be in sync' do
        allow(@provider).to receive(:expires_soon_or_expired).and_return(true)
        expect(@resource.property(:expiration).insync? 'unused').to be false
      end
    end
  end
end
