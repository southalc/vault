# Plan configures a Vault agent for use with an existing AppRole
# @param vault_addr The URL of the Vault service.
# @param role_id String - The RoleID of the Vault AppRole.
# @param secret_id String - The SecretID of the Vault AppRole.
# @param owner The user name that will own the Vault agent sink file.
# @param install_vault Install Vault using the "hashi_stack::repo" class.  Set
#   parameters for "hashi_stack::repo" in hiera to customize the installation.
#
plan vault_secrets::approle_agent (
  TargetSpec $targets,
  String $vault_addr,
  Sensitive $role_id,
  Sensitive $secret_id,
  String $owner,
  Boolean $install_vault = true,
) {
  if $install_vault {
    # Collects facts on targets and update the inventory
    run_plan('facts', 'targets' => $targets)
  }

  $results = apply($targets, '_catch_errors' => true) {
    Vault_secrets::Approle_agent { 'puppetserver':
      vault_addr    => $vault_addr,
      role_id       => $role_id.unwrap,
      secret_id     => $secret_id.unwrap,
      owner         => $owner,
      install_vault => $install_vault,
    }
  }

  $results.each |$result| {
    out::message("  Target: ${result.target}, ${result.message}")
  }
}

