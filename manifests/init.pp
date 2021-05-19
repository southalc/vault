# @summary Issue and renew PKI certificates from Hashicorp Vault
#
# @param vault_uri The complete URL of the the Hashicorp Vault certificate issuing role API endpoint
#
# @param auth_path The Vault path of the authentication provider used by Puppet certificates
#
# @param days_before_renewal The number of days before expiration where the host certificate will be re-issued
#
# @param cert_data A hash of values to be submitted with the certificate request.  The hash contents should
#   adhere to the keys/values supported/permitted by the PKI role and policy.  Basic default values are
#   defined in module hiera.
#
# @example Issue a host certificate from a Vault server with PKI secrets engine
#  class { 'vault':
#    vault_uri  => 'https://vault.example.com:8200/v1/pki/issue/example-com',
#    auth_path  => 'puppet-pki',
#  }
#
class vault (
  String $vault_uri,
  String $auth_path,
  Integer[1, 30] $days_before_renewal = 3,
  Hash $cert_data                     = {},
) {
  $vault_cert = fact('vault_cert')
  $cert = $vault_cert.dig('cert')
  $key = $vault_cert.dig('key')
  $ca_chain = $vault_cert.dig('ca_chain')
  $v = $vault_cert.dig('valid')
  $valid = $v ? {
    undef   => false,
    default => $v,
  }
  $x = $vault_cert.dig('days_remaining')
  $days_remaining = $x ? {
    undef   => 0,
    default => $x,
  }

  if !$valid or $days_remaining < $days_before_renewal {
    # Issue a new certificate from the Vault PKI endpoint
    $host_cert = vault_cert($vault_uri, $auth_path, $cert_data)

    # Create certificate and key files from the 'host_cert' hash data
    file {
      default:
        ensure => present,
        owner  => 'root',
        group  => 'root',
      ;
      $cert:
        mode    => '0644',
        content => $host_cert['certificate'],
      ;
      $key:
        mode    => '0600',
        content => $host_cert['private_key'],
      ;
      $ca_chain:
        mode    => '0644',
        content => join($host_cert['ca_chain'], "\n"),
        notify  => Exec['vault update-ca-trust'],
    }
  } else {
    # Ensure file resources are defined so other resources can depend on them
    file {
      default:
        ensure => present,
        owner  => 'root',
        group  => 'root',
      ;
      $cert:
        mode    => '0644',
      ;
      $key:
        mode    => '0600',
      ;
    }
  }

  exec { 'vault update-ca-trust':
    path        => '/sbin:/usr/sbin:/bin:/usr/bin',
    command     => lookup('vault::update_trust_cmd'),
    refreshonly => true,
  }
}

