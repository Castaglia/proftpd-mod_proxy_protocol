package ProFTPD::Tests::Modules::mod_proxy_protocol::sftp;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::ProxiedFTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  proxy_protocol_sftp_with_proxy => {
    order => ++$order,
    test_class => [qw(forking mod_proxy_protocol mod_sftp)],
  },

  proxy_protocol_sftp_without_proxy => {
    order => ++$order,
    test_class => [qw(forking mod_proxy_protocol mod_sftp)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
#  return testsuite_get_runnable_tests($TESTS);
  return qw(
    proxy_protocol_sftp_with_proxy
  );
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }
}

sub proxy_protocol_sftp_with_proxy {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy_protocol');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ssh2:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy_protocol.c' => {
        ProxyProtocolEngine => 'on',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(2);

      my $client = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port);
      $client->send_proxy_raw('1.1.1.1', '2.2.2.2', 111, 222);
      my $banner = $client->getline();
      chomp($banner);

      unless ($banner =~ /^SSH\-2\.0\-mod_sftp/) {
        die("Received unexpected banner from mod_sftp: '$banner'");
      }

      print $client "SSH-2.0-ProFTPD_mod_proxy_protocol_sftp_Test\r\n";
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 10) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});

  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
