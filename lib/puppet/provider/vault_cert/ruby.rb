require 'etc'
require 'json'

require "#{File.dirname(__FILE__)}/../../shared/vault_common.rb"

Puppet::Type.type(:vault_cert).provide(:ruby) do
	desc 'Issue certificates from Hashicorp Vault'

	mk_resource_methods

	def initialize(value={})
		super(value)
		@cert_dir = Facter.value(:vault_cert_dir)
		@property_flush = {}
	end

	def self.instances
		instances = []
		cert_dir = Facter.value(:vault_cert_dir)
		cert_filenames = Dir.glob("#{cert_dir}/*.json")
		cert_filenames.each do |info_file|
			name = File.basename(info_file, '.json')
			
			info_content, info_owner, info_group, info_mode = load_file(info_file)
			cert_info = JSON.parse(info_content)

			next unless ['data', 'cert_data', 'ca_chain_file', 'cert_file', 'key_file'].all? {|k| cert_info.key? k}

			ca_chain, ca_chain_owner, ca_chain_group, ca_chain_mode = load_file(cert_info['ca_chain_file'])
			cert, cert_owner, cert_group, cert_mode = load_file(cert_info['cert_file'])
			key, key_owner, key_group, key_mode = load_file(cert_info['key_file'])

			begin
				expiration = cert_info['data']['expiration']
			rescue
				expiration = nil
			end

			instances << new(
				ensure: :present,
				name: name,
				cert_data: cert_info['cert_data'],
				expiration: expiration,
				# Info file
				info_owner: info_owner,
				info_group: info_group,
				info_mode: info_mode,
				# CA Chain
				ca_chain_file: cert_info['ca_chain_file'],
				ca_chain_owner: ca_chain_owner,
				ca_chain_group: ca_chain_group,
				ca_chain_mode: ca_chain_mode,
				ca_chain: ca_chain,
				info_ca_chain: cert_info['data']['ca_chain'].join("\n"),
				# Certificate
				cert_file: cert_info['cert_file'],
				cert_owner: cert_owner,
				cert_group: cert_group,
				cert_mode: cert_mode,
				cert: cert,
				info_cert: [cert_info['data']['certificate'], cert_info['data']['issuing_ca']].join("\n"),
				# Private Key
				key_file: cert_info['key_file'],
				key_owner: key_owner,
				key_group: key_group,
				key_mode: key_mode,
				key: key,
				info_key: cert_info['data']['private_key']
			)
		end
		return instances
	end

	def self.prefetch(resources)
		instances.each do |prov|
			if (resource = resources[prov.name])
			resource.provider = prov
			end
		end
	end

	def exists?
		Puppet.info("property_hash includes ensure? #{@property_hash.include?(:ensure)}")
		@property_hash[:ensure] == :present
	end

	def create
		@property_flush[:ensure] = :present
	end

	def destroy
		@property_flush[:ensure] = :absent
	end

	def issue_cert
		Puppet.info("Requesting certificate #{@resource[:name]}")

		uri = URI(@resource[:vault_uri])
		raise Puppet::Error, "Unable to parse a hostname from #{@resource[:vault_uri]}" unless uri.hostname

		# Try known paths for trusted CA certificate bundles
		ca_trust = if File.exist?('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')
				'/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
			   elsif File.exist?('/etc/ssl/certs/ca-certificates.crt')
				'/etc/ssl/certs/ca-certificates.crt'
			   else
				nil
			   end
		raise Puppet::Error, 'Failed to get the trusted CA certificate file' if ca_trust.nil?

		http = http_create_secure(uri, ca_trust, @resource[:timeout])
		token = vault_get_token(http, @resource[:auth_path].delete('/'))
		secrets = vault_http_post(http, uri.path, token, @resource[:cert_data])
		response = vault_parse_data(secrets)

		return response
	end

	def self.load_file(file)
		if file && File.exists?(file)
			content = File.read(file)
			stat = File::Stat.new(file)
			owner = Etc.getpwuid(stat.uid).name
			group = Etc.getgrgid(stat.gid).name
			mode = sprintf("%04o", stat.mode & 07777)
			return content, owner, group, mode
		else
			return nil, nil, nil, nil
		end
	end

	def chown_file(file, owner, group)
		uid = owner ? Etc.getpwnam(owner).uid : nil
		gid = group ? Etc.getgrnam(group).gid : nil
		Puppet.info("Chowning #{file} to #{uid}:#{gid}")
		File.chown(uid, gid, file)
	end

	def chmod_file(file, mode)
		File.chmod(mode.to_i(8), file) if mode
	end

	def delete_if_exists(file)
		File.delete(file) if ! file.to_s.empty? && File.exist?(file)
	end

	def expires_soon_or_expired
		time_now = Time.now.to_i
		renewal_time = @property_hash[:expiration] - (@resource[:renewal_threshold] * 3600 * 24)
		return time_now >= renewal_time
	end

	def needs_issue?
		return true if @property_hash[:ensure] != :present
		return true if @property_hash[:cert_data] != @property_flush[:cert_data]
		return true if expires_soon_or_expired
	end

	def info_owner=(value)
		@property_flush[:info_owner] = value
	end

	def info_group=(value)
		@property_flush[:info_group] = value
	end

	def info_mode=(value)
		@property_flush[:info_mode] = value
	end

	def cert_data=(value)
		@property_flush[:cert_data] = value
	end

	def ca_chain_file=(value)
		@property_flush[:ca_chain_file] = value
	end

	def ca_chain_owner=(value)
		@property_flush[:ca_chain_owner] = value
	end
 
	def ca_chain_group=(value)
		@property_flush[:ca_chain_group] = value
	end

	def ca_chain_mode=(value)
		@property_flush[:ca_chain_mode] = value
	end

	def cert_file=(value)
		@property_flush[:cert_file] = value
	end

	def cert_owner=(value)
		@property_flush[:cert_owner] = value
	end
 
	def cert_group=(value)
		@property_flush[:cert_group] = value
	end

	def cert_mode=(value)
		@property_flush[:cert_mode] = value
	end

	def key_file=(value)
		@property_flush[:key_file] = value
	end

	def key_owner=(value)
		@property_flush[:key_owner] = value
	end
 
	def key_group=(value)
		@property_flush[:key_group] = value
	end

	def key_mode=(value)
		@property_flush[:key_mode] = value
	end

	def ca_chain=(value)
	end

	def cert=(value)
	end

	def key=(value)
	end

	def flush_file_attributes(file, owner, group, mode, force)
		# Update the file ownership if not in sync
		if force || (@property_flush.include?(owner) && @property_hash[owner] != @property_flush[owner]) || (@property_flush.include?(group) && @property_hash[group] != @property_flush[group])
			self.class.chown_file(file, @property_flush[owner], @property_flush[group])
			@property_hash[owner] = @property_flush[owner]
			@property_hash[group] = @property_flush[group]
		end

		# Update the file permissions if not in sync
		if force || (@property_flush.include?(mode) && @property_hash[mode] != @property_flush[mode])
			self.class.chmod_file(file, @property_flush[mode])
			@property_hash[mode] = @property_flush[mode]
		end
	end

	def flush_file(file, content, owner, group, mode)
		# If the file will be created (new, or moved), we must reset the attributes,
		# since Puppet may not have signalled a change by calling the setter methods
		force_reset_attributes = @property_hash.include?(content) || @property_hash[content].nil? || @property_hash[content].blank?

		# If the file path is being changed, delete the old file first and force all attributes
		# to be reset, since they won't be correct on the new file, even if they were
		# correct on the old file before
		if @property_flush.include?(file) && @property_hash[file] != @property_flush[file]
			self.class.delete_if_exists(@property_hash[file])
			force_reset_attributes = true

			# Indicate that we did change the file path
			@property_hash[file] = @property_flush[file]
		end

		if force_reset_attributes
			@property_flush[owner] = @resource[owner]
			@property_flush[group] = @resource[group]
			@property_flush[mode] = @resource[mode]
		end

		# Update the file content if not in sync
		if force_reset_attributes || (@property_flush.include?(content) && @property_hash[content] != @property_flush[content])
			File.write(@resource[file], @property_flush[content])
			@property_hash[content] = @property_flush[content]
		end

		flush_file_attributes(@property_hash[file], owner, group, mode, force_reset_attributes)
	end

	def flush
		info_file = "#{@cert_dir}/#{@resource[:name]}.json"

		if @property_flush[:ensure] == :absent
			self.class.delete_if_exists(@resource[:ca_chain_file])
			self.class.delete_if_exists(@resource[:cert_file])
			self.class.delete_if_exists(@resource[:key_file])
			self.class.delete_if_exists(info_file)
			return
		end

		if needs_issue?
			response = issue_cert

			info = JSON.generate({
				:data		   => response,
				:cert_data         => @resource[:cert_data],
				:ca_chain_file	   => @resource[:ca_chain_file],
				:cert_file 	   => @resource[:cert_file],
				:key_file	   => @resource[:key_file],
			})
			File.write(info_file, info)
			flush_file_attributes(info_file, :info_owner, :info_group, :info_mode, true)

			# These are read-only properties which will never
			# be set in the puppet resource, but we will set once
			# a cert has been issued.
			# These will be flushed to disk later if the is (@property_hash)
			# does not match the should (@resource)
			@property_flush[:ca_chain] = response['ca_chain'].join("\n")
			@property_flush[:cert] = [response['certificate'], response['issuing_ca']].join("\n")
			@property_flush[:key] = response['private_key']
		else
			flush_file_attributes(info_file, :info_owner, :info_group, :info_mode)

			# Re-read the info file to make sure the intended contents of the chain/cert/key files
			# are correct
			cert_info = JSON.parse(File.read(info_file))
			@property_flush[:ca_chain] = cert_info['data']['ca_chain'].join("\n")
			@property_flush[:cert] = [cert_info['data']['certificate'], cert_info['data']['issuing_ca']].join("\n")
			@property_flush[:key] = cert_info['data']['private_key']
		end

		flush_file(:ca_chain_file, :ca_chain, :ca_chain_owner, :ca_chain_group, :ca_chain_mode)
		flush_file(:cert_file, :cert, :cert_owner, :cert_group, :cert_mode)
		flush_file(:key_file, :key, :key_owner, :key_group, :key_mode)

	end

end