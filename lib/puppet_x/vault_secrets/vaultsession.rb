# frozen_string_literal: true

require 'puppet'
require 'uri'
require 'openssl'
require 'json'

# Class provides methods to interface with Hashicorp Vault
class VaultSession
  def initialize(args)
    # @summary Provide methods to interface with Hashicorp Vault
    # @param [Hash] args Configuration options for the Vault connection.
    # @option args [String] :uri Required The URL of a Vault API endpoint
    # @option args [Integer] :timeout Optional Seconds to wait for connection attempts. (5)
    # @option args [Boolean] :secure Optional When true, security certificates will be validated against the 'ca_file' (true)
    # @option args [String] :ca_file Optional path to a file containing the trusted certificate authority chain.
    # @option args [String] :token Optional token used to access the Vault API, otherwise attempts certificate authentication using the Puppet agent certificate.
    # @option args [String] :auth_path The Vault path of the "cert" authentication type for Puppet certificates
    # @option args [String] :auth_name The optional Vault certificate named role to authenticate against
    # @option args [Boolean] :fail_hard Optional Raise an exception on errors when true, or return an empty hash when false. (true)
    # @option args [String] :version The version of the Vault key/value secrets engine, either 'v1' or 'v2'. (v1)
    raise Puppet::Error, "The #{self.class.name} class requires a 'uri'." unless args.key?('uri')
    @uri = URI(args['uri'])
    raise Puppet::Error, "Unable to parse a hostname from #{args['uri']}" unless uri.hostname
    @fail_hard = if [true, false].include? args.dig('fail_hard')
                   args.dig('fail_hard')
                 else
                   true
                 end
    timeout = if args.dig('timeout').is_a? Integer
                args['timeout']
              else
                5
              end
    @version = if args.dig('version') == 'v2'
                 'v2'
               else
                 'v1'
               end
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = timeout
    http.read_timeout = timeout
    secure = true unless args.dig('secure') == false || @uri.scheme == 'http'
    if secure
      ca_trust = if args.dig('ca_trust').is_a? String
                   args['ca_trust']
                 else
                   nil
                 end
      http.use_ssl = true
      http.ssl_version = :TLSv1_2
      http.ca_file = get_ca_file(ca_trust)
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    elsif @uri.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    else
      http.use_ssl = false
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    @http = http
    token = if args.dig('token')
              args['token']
            else
              raise Puppet::Error, "An 'auth_path' must be defined when not using a token." unless args.key?('auth_path')
              get_token(args['auth_path'], args['auth_name'])
            end
    @headers = {
      'Content-Type': 'application/json',
      'X-Vault-Token': token,
    }
  end

  attr_accessor :uri, :http, :secure, :fail_hard

  def err_check(response)
    # @summary Consistent error handling for common failures
    # @param response An instance of Net::HTTPResponse
    # @return nil
    if response.is_a?(Net::HTTPNotFound)
      err_message = "Vault path not found. (#{response.code} from #{@uri})"
      raise Puppet::Error, append_api_errors(err_message, response) if fail_hard
      Puppet.debug append_api_errors(err_message, response)
    elsif !response.is_a?(Net::HTTPOK)
      err_message = "Vault request failed. (#{response.code}) from #{@uri})"
      raise Puppet::Error, append_api_errors(err_message, response) if fail_hard
      Puppet.debug append_api_errors(err_message, response)
    end
    nil
  end

  def append_api_errors(message, response)
    # @summary Add meaningful(maybe?) messages to errors
    # @param [String] :message The error string before appending any API errors.
    # @param [Net::HTTPResponse] :response The method will try to read errors from the response and append to 'message'
    # @return [String] The updated error message including any errors found in the response.
    errors = begin
               JSON.parse_json(response.body)['errors']
             rescue
               nil
             end
    message << " (api errors: #{errors})" if errors
    message
  end

  def parse_response(response, version = @version)
    # @summary Process an HTTP response as a JSON string and return Vault secrets
    # @param [Net::HTTPResponse] :response The object body will be parsed as JSON.
    # @param [String] :version The version of the Vault key/value secrets engine in the response, either 'v1' or 'v2' (v1)
    # @return [Hash] The returned hash contains the secret key/value pairs.
    begin
      output = if version == 'v2'
                 JSON.parse(response.body)['data']['data']
               else
                 JSON.parse(response.body)['data']
               end
    rescue
      nil
    end
    err_message = "Failed to parse #{version} key/value data from response body: (#{@uri_path})"
    raise Puppet::Error, err_message if output.nil? && fail_hard
    Puppet.debug err_message if output.nil?
    output ||= {}
    v1_warn = "Data from '#{@uri_path}' was requested as key/value v2, but may be v1 or just be empty."
    Puppet.debug v1_warn if @version == 'v2' &&  output.empty?
    v2_warn = "Data from '#{@uri_path}' appears to be key/value v2, but was requested as v1"
    Puppet.debug v2_warn if @version == 'v1' &&  output.dig('data') && output.dig('metadata')
    output
  end

  def get(uri_path = @uri.path, version = @version)
    # @summary Submit an HTTP GET request to the given 'uri_path'
    # @param [String] :uri_path A relative path component of a URI, or reference URI.path
    # @param [String] :version The version of the Vault key/value secrets engine (v1)
    # @retrun [Hash] A hash containing the secret key/value pairs.
    @uri_path = uri_path
    request = Net::HTTP::Get.new(uri_path)
    @headers.each do |key, value|
      request[key] = value
    end
    response = http.request(request)
    err_check(response)
    parse_response(response, version)
  end

  def post(uri_path = @uri.path, data = {})
    # @summary Submit an http post request to the given 'uri_path'
    # @param [String] :uri_path A relative path component of a URI, or reference to a URI.path.
    # @param [Hash] :data A hash of values to submit with the HTTP POST request.
    # return [Net::HTTPResponse]
    @uri_path = uri_path
    request = Net::HTTP::Post.new(uri_path)
    # This function may be called before instance variable is defined as part of initialize
    @headers ||=  {}
    @headers.each do |key, value|
      request[key] = value
    end
    request.body = data.to_json
    response = http.request(request)
    err_check(response)
    response
  end

  def get_token(auth_path, auth_name)
    # @summary Use the Puppet host certificate and private key to authenticate to Vault
    # @param [String] :auth_path The Vault path of the "cert" authentication type for Puppet
    # @param [String] :auth_name The optional Vault named certificate role to authenticate against
    # @return [String] A Vault token.

    # Get the client certificate and private key files for Vault authenticaion
    hostcert = File.expand_path(Puppet.settings[:hostcert])
    hostprivkey = File.expand_path(Puppet.settings[:hostprivkey])
    http.cert = OpenSSL::X509::Certificate.new(File.read(hostcert))
    http.key = OpenSSL::PKey::RSA.new(File.read(hostprivkey))

    data = auth_name ? { name: auth_name } : nil

    # Submit the request to the auth_path login endpoint
    response = post("/v1/auth/#{auth_path.gsub(%r{/$}, '')}/login", data)
    err_check(response)

    # Extract the token value from the response
    begin
      token = JSON.parse(response.body)['auth']['client_token']
    rescue
      raise Puppet::Error, 'Unable to parse client_token from vault response.'
    end
    raise Puppet::Error, 'No client_token found.' if token.nil?
    token
  end

  def get_ca_file(ca_trust)
    # @summary Try known paths for trusted CA certificates when not specified
    # @param [String] :ca_trust The path to a trusted certificate authority file. If nil, some defaults are attempted.
    # @return [String] The verified file path to a trusted certificate authority file.
    ca_file = if ca_trust && File.exist?(ca_trust)
                ca_trust
              elsif File.exist?('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')
                '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
              elsif File.exist?('/etc/ssl/certs/ca-certificates.crt')
                '/etc/ssl/certs/ca-certificates.crt'
              else
                nil
              end
    raise Puppet::Error, 'Failed to get the trusted CA certificate file.' if ca_file.nil?
    ca_file
  end
end
