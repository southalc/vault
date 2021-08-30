# @summary 
class vault_secrets::vault_cert (
  $purge=false
) {

  file {
    $::vault_cert_dir:
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => '0755'
  }

  if $purge {
    resources {
      'vault_cert':
        purge => true;
    }
  }
}
