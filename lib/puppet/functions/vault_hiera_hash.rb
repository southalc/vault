# @summary Custom hiera back-end for Hashicorp Vault key/value secrets engine
#
Puppet::Functions.create_function(:vault_hiera_hash) do
  # @param options Hash containing:
  # @option uri        Required. The complete URL to the API endpoint of a Vault key/value secrets path.
  # @option ca_trust   Required. The path to trusted CA certificate chain file.
  # @option token_file Optional. Path to a file that contains a Vault token, otherwise will try PKI auth with Puppet cert
  # @option auth_path  Optional. The Vault path for the "cert" authentication type used with Puppet certificates
  # @option version    Optional. Defaults to Vault key/value secrets engine v1 unless this is set to 'v2'.
  # @option timeout    Optional. Default is 5 seconds.
  # @param context     Default parameter used for caching
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
