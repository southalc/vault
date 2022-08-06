require 'etc'
require 'json'
require 'time'

require "#{File.dirname(__FILE__)}/../../../puppet_x/vault_secrets/vaultsession.rb"

Puppet::Type.type(:vault_ssh_cert).provide(:vault_ssh_cert) do
  desc 'Issue SSH certificates from Hashicorp Vault'

  mk_resource_methods

  commands :ssh_keygen => "ssh-keygen"

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  def self.instances
    # @summary Enables resource discovery for the vault_ssh_cert custom type.
    instances = []
    cert_filenames = Dir.glob("/etc/ssh/ssh_host_*_key-cert.pub")
    cert_filenames.each do |cert_file|
      owner, group, mode = load_file(cert_file)

      begin
        expiration, valid_principals = self.parse_cert_file cert_file
      rescue => error
        expiration = nil
        valid_principals = []
      end

      public_key_file = cert_file.sub(/(.*)-cert(\.pub?)$/, '\1\2')

      instances << new(
        ensure: :present,
        name: public_key_file,
        file: cert_file,
        expiration: expiration,
        valid_principals: valid_principals,
        owner: owner,
        group: group,
        mode: mode,
      )
    end
    instances
  end

  def self.prefetch(resources)
    instances.each do |prov|
      if (resource = resources[prov.name])
        resource.provider = prov
      end
    end
  end

  def self.parse_cert_file(file)
    expiration = nil
    valid_principals = []
    output = ssh_keygen("-L", "-f", file).chomp
    output.each_line do |line|
      next unless matches = /\s+Valid:\s+from .* to (.*)/.match(line)
      expiration = Time.parse(matches[1]).to_i
      break
    end

    in_principals_section = false
    output.each_line do |line|
      if in_principals_section
        # Check if starting another section
        if /^\s+(.*):/.match(line)
          in_principals_section = false
          next
        end
        valid_principals << line.strip
      else
        in_principals_section = true if matches = /^\s+Principals:\s*$/.match(line)
        next
      end
    end

    [expiration, valid_principals]
  end

  def exists?
    @property_hash[:ensure] == :present
  end

  def create
    @property_flush[:ensure] = :present
  end

  def destroy
    @property_flush[:ensure] = :absent
  end

  def self.get_ca_trust
    # Try known paths for trusted CA certificate bundles
    if File.exist?('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')
      '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    elsif File.exist?('/etc/ssl/certs/ca-certificates.crt')
      '/etc/ssl/certs/ca-certificates.crt'
    else
      raise Puppet::Error, 'Failed to get the trusted CA certificate file'
    end
  end

  def issue_cert
    # @summary Request a certificate from the Vault API.
    Puppet.info("Requesting certificate for #{@resource[:name]}")
    ca_trust = self.class.get_ca_trust
    connection = {
      'uri'       => @resource[:vault_uri],
      'auth_path' => @resource[:auth_path],
      'auth_name' => @resource[:auth_name],
      'ca_trust'  => ca_trust,
      'timeout'   => @resource[:timeout],
    }
    request_data = {
      :cert_type        => @resource[:cert_type],
      :public_key       => File.read(@resource[:name]),
      :ttl              => @resource[:ttl],
      :valid_principals => !@resource[:valid_principals].empty? ? @resource[:valid_principals].join(',') : nil,
    }.select {|k, v| !v.nil? }
    # Use the Vault class for the lookup
    vault = VaultSession.new(connection)
    begin
      Puppet.warning(request_data)
      response = vault.post(URI(@resource[:vault_uri]).path, request_data)
      vault.parse_response(response)
    rescue => error
      raise "Failed to issue cert from vault. Check your TTL is within the max, that your public key is a supported type, etc (#{error})"
    end
  end

  def self.load_file(file)
    if file && File.exist?(file)
      stat = File::Stat.new(file)
      owner = Etc.getpwuid(stat.uid).name
      group = Etc.getgrgid(stat.gid).name
      mode = '%04o' % (stat.mode & 0o7777)
      [owner, group, mode]
    else
      [nil, nil, nil]
    end
  end

  def self.chown_file(file, owner, group)
    uid = owner ? Etc.getpwnam(owner).uid : nil
    gid = group ? Etc.getgrnam(group).gid : nil
    File.chown(uid, gid, file) unless uid.nil? && gid.nil?
  end

  def self.chmod_file(file, mode)
    File.chmod(mode.to_i(8), file) if mode
  end

  def self.delete_if_exists(file)
    File.delete(file) if !file.to_s.empty? && File.exist?(file)
  end

  def expires_soon_or_expired
    # @summary Determine the certificate expiration date.
    time_now = Time.now.to_i
    expiry_time = @property_hash[:expiration]
    renewal_threshold_seconds = @resource[:renewal_threshold] * 3600 * 24
    renewal_time = expiry_time - renewal_threshold_seconds
    time_now >= renewal_time
  end

  def needs_issue?
    return true if @property_hash[:ensure] != :present
    return true if expires_soon_or_expired
    return true if @property_flush.include?(:valid_principals) and @property_hash[:valid_principals] != @property_flush[:valid_principals]
    false
  end

  def owner=(value)
    @property_flush[:owner] = value
  end

  def group=(value)
    @property_flush[:group] = value
  end

  def mode=(value)
    @property_flush[:mode] = value
  end

  def valid_principals=(value)
    @property_flush[:valid_principals] = value
  end

  def expiration=(value)
    # Property should be read only, do not change
  end

  def flush_attributes(force = false)
    # Update the file ownership if not in sync
    if force || (@property_flush.include?(:owner) && @property_hash[:owner] != @property_flush[:owner]) || (@property_flush.include?(:group) && @property_hash[:group] != @property_flush[:group])
      self.class.chown_file(@resource[:file], @property_flush[:owner], @property_flush[:group])
      @property_hash[:owner] = @property_flush[:owner]
      @property_hash[:group] = @property_flush[:group]
    end

    # Update the file permissions if not in sync
    # rubocop:disable Style/GuardClause
    if force || (@property_flush.include?(:mode) && @property_hash[:mode] != @property_flush[:mode])
      self.class.chmod_file(@resource[:file], @property_flush[:mode])
      @property_hash[:mode] = @property_flush[:mode]
    end
    # rubocop:enable Style/GuardClause
  end

  def flush_file(content)
    # If the path is being changed, remove the old file
    if @property_hash[:file] != @property_flush[:file]
      self.class.delete_if_exists(@property_hash[:file])
    end

    File.write(@resource[:file], content)
    @property_flush[:owner] = @resource[:owner]
    @property_flush[:group] = @resource[:group]
    @property_flush[:mode] = @resource[:mode]
    flush_attributes(true)
  end

  def flush
    if @property_flush[:ensure] == :absent
      self.class.delete_if_exists(@resource[:file])
      # Remove all other attributes so that `puppet resource`
      # shows the correct state after removal
      @property_hash = @property_hash.slice(:ensure)
      return
    end

    if needs_issue?
      response = issue_cert
      flush_file(response["signed_key"])
    else
      flush_attributes
    end
  end
end
