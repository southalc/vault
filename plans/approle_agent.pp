# Plan configures a Vault agent for use with an existing AppRole
# @param action Install or remove the specified Vault agent service
# @param application Used as a component resource names. The Vault agent sink is: "/run/vault-${owner}/${application}.token"
# @param vault_addr The URL of the Vault service.
# @param role_id String - The RoleID of the Vault AppRole.
# @param secret_id String - The SecretID of the Vault AppRole.
# @param owner The user name that will own the Vault agent sink file.
# @param install_vault Install Vault using the "hashi_stack::repo" class.  Set
#   parameters for "hashi_stack::repo" in hiera to customize the installation.
#
plan vault_secrets::approle_agent (
  TargetSpec $targets,
  String $application,
  String $vault_addr,
  Sensitive $role_id,
  Sensitive $secret_id,
  String $owner,
  Enum['install', 'remove'] $action = 'install',
  Boolean $install_vault            = true,
) {
  # Collect facts on targets
  run_plan('facts', 'targets' => $targets)

  $results = apply($targets, '_catch_errors' => true) {
    # Would rather have an 'ensure' parameter for the plan, but it does not work
    $ensure = $action ? {
      'remove' => 'absent',
      default  => 'present',
    }
    Vault_secrets::Approle_agent { $application:
      ensure        => $ensure,
      vault_addr    => $vault_addr,
      role_id       => $role_id.unwrap,
      secret_id     => $secret_id.unwrap,
      owner         => $owner,
      install_vault => $install_vault,
    }
  }

  $results.each |$result| {
    if $result.ok {
      $result.report['logs'].each |$log| {
        out::message("${log['source']}: ${log['message']}")
      }
      out::message("Target summary: ${result.target}, ${result.message}")
    } else {
      out::message("${result.error} - ${result.message}")
    }
  }
}
