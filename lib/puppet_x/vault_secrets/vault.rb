# frozen_string_literal: true

require 'puppet'
require 'uri'
require 'openssl'
require 'json'

# Class provides methods to interface with Hashicorp Vault
class Vault
  def initialize(args)
    # @args - Hash May contain the following keys:
    # uri       String  Required The URL for this session
    # timeout   Integer Optional Seconds to wait for connection attempts. (5)
    # secure    Boolean Optional When true, security certificates will be validated against the 'ca_file' (true)
    # ca_file   String  Optional The path to a file containing the trusted certificate authority chain.
    # token     String  Optional The token used to access the Vault API, else you can use get_token()
    # auth_path String  The Vault path of the "cert" authentication type for Puppet certificates
    # fail_hard Boolean Optional Raise an exception on errors when true, or return an empty hash when false. (true)
    # version   String  Optional The version of the Vault key/value secrets engine, either 'v1' or 'v2'. (v1)
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
      raise Puppet::Error, "A secure connection requires a 'ca_trust' file." unless args.key?('ca_trust')
      raise Puppet::Error, "The 'ca_trust' file was not found: #{args['ca_trust']}" unless File.file?(args['ca_trust'])
      http.use_ssl = true
      http.ssl_version = :TLSv1_2
      http.ca_file = args['ca_trust']
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
              get_token(args['auth_path'])
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
      err_message = "#{response.code} - URL path not found: #{@uri_path}}"
      raise Puppet::Error, append_api_errors(err_message, response) if fail_hard
      Puppet.debug append_api_errors(err_message, response)
    elsif !response.is_a?(Net::HTTPOK)
      err_message = "#{response.code} - HTTP request failed to #{@uri_path}"
      raise Puppet::Error, append_api_errors(err_message, response) if fail_hard
      Puppet.debug append_api_errors(err_message, response)
    end
    nil
  end

  def append_api_errors(message, response)
    # @summary Add meaningful(maybe?) messages to errors
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
    # @param   response - An instance of Net::HTTPResponse
    # @param   version  - The version of the Vault key/value secrets engine in the response, either 'v1' or 'v2' (v1)
    # @return  Hash of Vault secrets
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
    # @param  uri_path A relative path component of a URI, or reference URI.path
    # @param  version The version of the Vault key/value secrets engine (v1)
    # @retrun Hash of secrets from parse_response
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
    # @param uri_path String - A relative path component of a URI, or reference URI.path
    # @param data Hash   - Values to submit with the POST request
    # return An instance of Net::HTTPResponse
    @uri_path = uri_path
    request = Net::HTTP::Post.new(uri_path)
    # This function may be called before instance variable is defined as part of initialize
    @headers ||=  {}
    @headers.each do |key, value|
      request[key] = value
    end
    request.set_form_data(data)
    response = http.request(request)
    err_check(response)
    response
  end

  def get_token(auth_path)
    # @summary Use the Puppet host certificate and private key to authenticate to Vault
    # @param auth_path The Vault path of the "cert" authentication type for Puppet
    # @return A Vault token as a string

    # Get the client certificate and private key files for Vault authenticaion
    hostcert = File.expand_path(Puppet.settings[:hostcert])
    hostprivkey = File.expand_path(Puppet.settings[:hostprivkey])
    http.cert = OpenSSL::X509::Certificate.new(File.read(hostcert))
    http.key = OpenSSL::PKey::RSA.new(File.read(hostprivkey))

    # Submit the request to the auth_path login endpoint
    response = post("/v1/auth/#{auth_path.delete_suffix('/')}/login")
    err_check(response)

    # Extract the token value from the response
    begin
      token = JSON.parse(response.body)['auth']['client_token']
    rescue
      raise Puppet::Error, 'Unable to parse client_token from vault response'
    end
    raise Puppet::Error, 'No client_token found' if token.nil?
    token
  end
end
