# @summary Configure a Vault agent for use with an existing AppRole and save the
#   resulting token to a sink file at "/run/vault-${owner}/${title}.token"
#
# @param ensure Add or remove the Vault agent configuration.
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
  Enum['present', 'absent'] $ensure        = 'present',
  Boolean                   $install_vault = true,
) {
  if $title !~ /^[a-zA-Z0-9_]*$/ {
    fail('The resource name only supports alpha-numeric characters and underscores')
  }

  $sink_file = "/run/vault-${owner}/${title}.token"
  $approle_id_file = "/etc/vault/${title}_role"
  $approle_secret_file = "/etc/vault/${title}_secret"
  $agent_config_file = "/etc/vault/${title}_agent.json"

  if $ensure == 'present' {
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
      content => epp('vault_secrets/tmpfiles.epp', { owner => $owner, }),
    }

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
      },
    }

    file { $agent_config_file:
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
      content => epp('vault_secrets/agent_service.epp', { name => $title, }),
    }

    systemd::unit_file { "${title}-vault-token.service":
      content => epp('vault_secrets/token_service.epp', {
          owner     => $owner,
          sink_file => $sink_file,
        }
      ),
    }

    systemd::unit_file { "${title}-vault-token.path":
      enable  => true,
      active  => true,
      content => epp('vault_secrets/token_path.epp', {
          name      => $title,
          sink_file => $sink_file,
        }
      ),
    }
    # END ensure => 'present'
  } else {
    systemd::tmpfile { "${title}_vault-agent.conf":
      ensure => 'absent',
    }

    file { [$sink_file, $approle_id_file, $approle_secret_file, $agent_config_file]:
      ensure  => 'absent',
      require => [
        Systemd::Unit_file["${title}-vault-agent.service"],
        Systemd::Unit_file["${title}-vault-token.service"],
        Systemd::Unit_file["${title}-vault-token.path"],
      ],
    }

    systemd::unit_file { [
        "${title}-vault-agent.service",
        "${title}-vault-token.service",
        "${title}-vault-token.path",
      ]:
        ensure => 'absent',
    }
  }
}
