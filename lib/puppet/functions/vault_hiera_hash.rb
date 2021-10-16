# frozen_string_literal: true

# Custom hiera back-end for Hashicorp Vault key/value secrets engines v1 and v2
Puppet::Functions.create_function(:vault_hiera_hash) do
  # @param options uri, ca_trust, token_file, auth_path, version, timeout, context
  # @option options [String] :uri        Required. The complete URL to the API endpoint for Hashicorp Vault key/value secrets.
  # @option options [String] :ca_trust   Optional path to a trusted CA certificate chain file.  Will try system defaults for RedHat/Debian if not set.
  # @option options [String] :token_file The path to a file that contains a Vault token. When not defined it will try PKI auth with Puppet cert.
  # @option options [String] :auth_path  Optional. The Vault path for the "cert" authentication type used with Puppet certificates.
  # @option options [String] :version    The Vault key/value secrets engine will always use 'v1' unless set to 'v2' here.
  # @option options [Integer] :timeout   Optional value for tuning HTTP timeouts. Default is 5 seconds.
  # @param context
  # @return [Hash] All key/value pairs from the given Vault path will be returned to hiera
  dispatch :vault_hiera_hash do
    param 'Hash', :options
    param 'Puppet::LookupContext', :context
  end

  require "#{File.dirname(__FILE__)}/../../puppet_x/vault_secrets/vault.rb"

  def vault_hiera_hash(options, context)
    err_message = "The vault_hiera_hash function requires one of 'uri' or 'uris'"
    raise Puppet::DataBinding::LookupError, err_message unless options.key?('uri')

    Puppet.debug "Using Vault URL: #{options['uri']}"

    connection = {}
    options.each do |key, value|
      connection[key] = value
    end

    if options.key?('token_file')
      token = File.read(options['token_file']).strip
      connection['token'] = token
    end

    # Hiera lookups should not fail hard when data is not found
    connection['fail_hard'] = false

    # Use the Vault class for the lookup
    data = Vault.new(connection).get

    context.not_found if data.empty? || !data.is_a?(Hash)
    context.cache_all(data)
    data
  end
end
