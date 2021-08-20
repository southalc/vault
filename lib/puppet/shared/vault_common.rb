# private functions used by the vault module

require 'puppet'
require 'uri'
require 'openssl'
require 'json'

private

def http_create_secure(uri, ca_trust, timeout = 5)
  # @summary Create a new 'Net::HTTP' instance with strong security
  # @param uri An instance of URI
  # @param ca_trust A file containing the trusted certificate chain of the Vault server
  # @param timeout The time in seconds to wait for an http response
  http = Net::HTTP.new(uri.host, uri.port)
  http.open_timeout = timeout
  http.read_timeout = timeout
  http.use_ssl = uri.scheme == 'https'
  http.ssl_version = :TLSv1_2
  http.ca_file = ca_trust
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http
end

def vault_http_get(http, uri_path, token)
  # @summary Submit an http get request to Vault
  # @param http An instance of 'Net::HTTP' as created by the http_create_secure method
  # @param uri_path A relative path component of a URI, or reference URI.path
  # @param token A Vault token with policy access to the uri_path
  request = Net::HTTP::Get.new(uri_path)
  request['X-Vault-Token'] = token
  request['Content-Type'] = 'application/json'
  response = http.request(request)
  err_message = 'Failed to obtain secrets from Vault: %{code}' % { code: response.code }
  raise Puppet::Error, append_api_errors(err_message, response) unless response.is_a?(Net::HTTPOK)
  response
end

def vault_http_post(http, uri_path, token, data)
  # @summary Submit an http post request to Vault
  request = Net::HTTP::Post.new(uri_path)
  request['X-Vault-Token'] = token
  request['Content-Type'] = 'application/json'
  request.set_form_data(data)
  response = http.request(request)
  data = if response.is_a?(Net::HTTPOK)
           response
         elsif response.code.to_s == '404'
           {}
         else
           err_message = 'Failed to obtain secrets from Vault: %{code}' % { code: response.code }
           raise Puppet::Error, append_api_errors(err_message, response)
         end
  data
end

def vault_parse_data(secrets, version = 'v1')
  # @summary Process a JSON response from Vault
  # @param secrets The result of vault_http_get or vault_http_post methods
  # @param version The version of the response to process
  begin
    data = if version == 'v2'
             JSON.parse(secrets.body)['data']['data']
           else
             JSON.parse(secrets.body)['data']
           end
  rescue
    # Return an empty hash when secrets fails to parse
    data = {}
  end
  data
end

def vault_get_token(http, auth_path)
  # @summary Use the Puppet host certificate and private key to authenticate to Vault
  # @param http An instance of Net::HTTP
  # @param auth_path The Vault path of the "cert" authentication type for Puppet
  # @return The Vault token obtained by successful authentication

  # Get the client certificate and private key files for Vault authenticaion
  hostcert = File.expand_path(Puppet.settings[:hostcert])
  hostprivkey = File.expand_path(Puppet.settings[:hostprivkey])
  http.cert = OpenSSL::X509::Certificate.new(File.read(hostcert))
  http.key = OpenSSL::PKey::RSA.new(File.read(hostprivkey))

  # Submit the request to the auth_path login endpoint
  request = Net::HTTP::Post.new("/v1/auth/#{auth_path}/login")
  response = http.request(request)
  err_message = "Received #{response.code} response code from vault for authentication"
  raise Puppet::Error, append_api_errors(err_message, response) unless response.is_a?(Net::HTTPOK)

  # Extract the token value from the response
  begin
    token = JSON.parse(response.body)['auth']['client_token']
  rescue StandardError
    raise Puppet::Error, 'Unable to parse client_token from vault response'
  end

  raise Puppet::Error, 'No client_token found' if token.nil?
  token
end

def append_api_errors(message, response)
  # @summary Add meaningful(?) messages to errors
  errors = begin
             JSON.parse(response.body)['errors']
           rescue StandardError
             nil
           end
  message << " (api errors: #{errors})" if errors
end
