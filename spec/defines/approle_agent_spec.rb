# frozen_string_literal: true

require 'spec_helper'

describe 'vault_secrets::approle_agent' do
  let(:title) { 'namevar' }
  let(:params) do
    {
      vault_addr: 'https://vault.example.com:8200',
      role_id: 'role_guid',
      secret_id: 'secret_guid',
      owner: 'tester',
      install_vault: false,
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
