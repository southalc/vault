# @summary Configure a Vault agent for use with an existing AppRole and save the
#   resulting token to a sink file at "/run/vault-${owner}/${title}.token"
#
# @param vault_addr The URL of the Vault service.
#
# @param role_id The RoleID of the Vault AppRole.
#
# @param secret_id The SecretID of the Vault AppRole.
#
# @param owner The user name that will own the Vault agent sink file.
#
# @param install_vault Install Vault using the "hashi_stack::repo" class.  Use
#   hiera to set parameters for customizing the installation.
#
# @see https://www.vaultproject.io/docs/auth/approle
#
# @note The defined type name permits only alpha-numeric characters and underscores.
#
# @example Create a Vault agent for use with vault_hiera_hash
#   vault_secrets::approle_agent { 'puppetserver':
#      vault_addr => 'https://vault.example.com:8200',
#      role_id    => 'your_roleId_guid',
#      secret_id  => 'your_secretId_guid',
#      owner      => 'pe-puppet',
#    }
#
define vault_secrets::approle_agent (
  String $vault_addr,
  String $role_id,
  String $secret_id,
  String $owner,
  Boolean $install_vault = true,
) {
  if $title !~ /^[a-zA-Z0-9_]*$/ {
    fail('The resource name only supports alpha-numeric characters and underscores')
  }

  $sink_file = "/run/vault-${owner}/${title}.token"

  if $install_vault {
    include hashi_stack::repo

    package { 'vault':
      ensure  => installed,
      require => Class['Hashi_stack::Repo'],
    }
  }

  file { default:
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    ;
    '/etc/vault':
    ;
    '/run/vault':
    ;
    "/run/vault-${owner}":
      owner => $owner,
    ;
  }

  # systemd tmpfile entry ensures directories are created on boot
  systemd::tmpfile { "${title}_vault-agent.conf":
    content => @("END"),
               # FILE MANAGED BY PUPPET
               # Create directories used by the Vault agent
               #Type Path          Mode  UID   GID       Age Argument
               d!    /run/vault    0700  root  root      -
               d!    /run/vault-${owner} 0700  ${owner}  root  -
               |END
  }

  $approle_id_file = "/etc/vault/${title}_role"
  $approle_secret_file = "/etc/vault/${title}_secret"

  file { default:
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      require => File['/etc/vault'],
    ;
    $approle_id_file:
      content => Sensitive($role_id),
    ;
    $approle_secret_file:
      content => Sensitive($secret_id),
    ;
  }

  # Define the AppRole configuration for Vault agent
  $agent_conf = {
    exit_after_auth => false,
    pid_file        => "/run/vault/${title}_vault-agent.pid",
    vault           => { address => $vault_addr, },
    auto_auth       => {
      method       => {
        type       => 'approle',
        mount_path => 'auth/approle',
        config     => {
          role_id_file_path                   => $approle_id_file,
          secret_id_file_path                 => $approle_secret_file,
          remove_secret_id_file_after_reading => false,
        },
      },
      sinks         => [
        sink   => {
          type   => file,
          config => { path => $sink_file, },
        },
      ],
    }
  }

  file { "/etc/vault/${title}_agent.json":
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
    require => File['/etc/vault'],
    notify  => Service["${title}-vault-agent.service"],
    content => to_json_pretty($agent_conf),
  }

  systemd::unit_file { "${title}-vault-agent.service":
    enable  => true,
    active  => true,
    require => File['/run/vault'],
    content => @("END"/$),
               # FILE MANAGED BY PUPPET
               [Unit]
               Description=Vault agent - ${title}
               Wants=${title}-vault-token.path
               
               [Service]
               PIDFile=/run/vault/vault-agent.pid
               ExecStart=/usr/bin/vault agent -config=/etc/vault/${title}_agent.json
               ExecReload=/bin/kill -HUP \$MAINPID
               KillMode=process
               KillSignal=SIGTERM
               Restart=on-failure
               RestartSec=42s
               LimitMEMLOCK=infinity
               
               [Install]
               WantedBy=multi-user.target
               |END
  }

  systemd::unit_file { "${title}-vault-token.service":
    enable  => true,
    active  => true,
    content => @("END"),
               # FILE MANAGED BY PUPPET
               [Service]
               Type=simple
               ExecStart=/bin/chown ${owner} ${sink_file}
               |END
  }

  systemd::unit_file { "${title}-vault-token.path":
    enable  => true,
    active  => true,
    content => @("END"),
               # FILE MANAGED BY PUPPET
               [Unit]
               Description=Monitor Vault token file
               Wants=network.target network-online.target
               After=network.target network-online.target
               
               [Path]
               PathChanged=${sink_file}
               Unit=${title}-vault-token.service
               |END
  }
}

