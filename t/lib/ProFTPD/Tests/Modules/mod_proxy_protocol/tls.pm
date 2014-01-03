package ProFTPD::Tests::Modules::mod_proxy_protocol::tls;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use Net::Cmd qw(CMD_OK CMD_MORE);

use ProFTPD::TestSuite::ProxiedFTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  proxy_protocol_tls_login_with_proxy => {
    order => ++$order,
    test_class => [qw(forking mod_proxy_protocol mod_tls)],
  },

  proxy_protocol_tls_login_with_proxy_useimplicitssl => {
    order => ++$order,
    test_class => [qw(forking mod_proxy_protocol mod_tls)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  Net-SSLeay
  #  IO-Socket-SSL

  my $required = [qw(
    Net::SSLeay
    IO::Socket::SSL
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

#  return testsuite_get_runnable_tests($TESTS);
  return qw(
    proxy_protocol_tls_login_with_proxy_useimplicitssl
  );
}

sub proxy_protocol_tls_login_with_proxy {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy_protocol');

  my $server_cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_tls/ca-cert.pem");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'netio:10 proxy_protocol:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy_protocol.c' => {
        ProxyProtocolEngine => 'on',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $server_cert_file,
        TLSCACertificateFile => $ca_file,
      },
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

  require IO::Socket::SSL;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(2);

      my $client = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port,
        ['TCP4', '1.1.1.1', '2.2.2.2', 111, 222]);
      my $ok = $client->command("AUTH", "TLS")->response();
      unless ($ok == CMD_OK || $ok == CMD_MORE) {
        die($client->message);
      }

      my $ssl_opts = {
        SSL_version => 'SSLv23',
      };

      my $ssl_client = IO::Socket::SSL->start_SSL($client, %$ssl_opts);
      unless ($ssl_client) {
        die("TLS handshake failed: " . IO::Socket::SSL::errstr());
      }

      push(@IO::Socket::SSL::ISA, 'Net::Cmd');

      $ok = $ssl_client->command("USER", $setup->{user})->response();
      unless ($ok == CMD_OK || $ok == CMD_MORE) {
        die($client->message);
      }

      $ok = $ssl_client->command("PASS", $setup->{passwd})->response();
      unless ($ok == CMD_OK || $ok == CMD_MORE) {
        die($client->message);
      }

      $ok = $ssl_client->command("QUIT")->response();
      unless ($ok == CMD_OK) {
        die($client->message);
      }
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

sub proxy_protocol_tls_login_with_proxy_useimplicitssl {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy_protocol');

  my $server_cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_tls/ca-cert.pem");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy_protocol.c' => {
        ProxyProtocolEngine => 'on',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $server_cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'UseImplicitSSL',
      },
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

  require IO::Socket::SSL;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(2);

      my $client = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port,
        ['TCP4', '1.1.1.1', '2.2.2.2', 111, 222]);

      my $ssl_opts = {
        SSL_version => 'SSLv23',
      };

      my $ssl_client = IO::Socket::SSL->start_SSL($client, %$ssl_opts);
      unless ($ssl_client) {
        die("TLS handshake failed: " . IO::Socket::SSL::errstr());
      }

      push(@IO::Socket::SSL::ISA, 'Net::Cmd');

      my $ok = $ssl_client->response();
      unless ($ok == CMD_OK || $ok == CMD_MORE) {
        die($client->message);
      }

      $ok = $ssl_client->command("USER", $setup->{user})->response();
      unless ($ok == CMD_OK || $ok == CMD_MORE) {
        die($client->message);
      }

      $ok = $ssl_client->command("PASS", $setup->{passwd})->response();
      unless ($ok == CMD_OK || $ok == CMD_MORE) {
        die($client->message);
      }

      $ok = $ssl_client->command("QUIT")->response();
      unless ($ok == CMD_OK) {
        die($client->message);
      }
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
