package ProFTPD::Tests::Modules::mod_dnsbl;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use Net::Cmd qw(CMD_OK);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::ProxiedFTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

# NOTE: We need to use mod_proxy_protocol for these DNSBL tests so that we
# can dicate the IP address of the connecting client.  For example, per
# RFC 5782, DNSBLs should always have an entry for "127.0.0.2" for testing.

my $TESTS = {
  dnsbl_policy_allow_deny => {
    order => ++$order,
    test_class => [qw(forking mod_dnsbl mod_proxy_protocol)],
  },

  dnsbl_policy_deny_allow => {
    order => ++$order,
    test_class => [qw(forking mod_dnsbl mod_proxy_protocol)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub dnsbl_policy_allow_deny {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'dnsbl');

  my $dnsbl_domain = 'bl.spamcop.net';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_dnsbl.c' => {
        DNSBLEngine => 'on',
        DNSBLLog => $setup->{log_file},
        DNSBLDomain => $dnsbl_domain,
        DNSBLPolicy => 'allow,deny',
      },

      'mod_proxy_protocol.c' => {
        ProxyProtocolEngine => 'on',
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

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(2);

      eval { ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port, 1,
        ['TCP4', '127.0.0.2', '2.2.2.2', 111, 222]) };
      unless ($@) {
        die("Connection succeeded unexpectedly");
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /found record for DNS name '2\.0\.0\.127\.$dnsbl_domain'/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected DNSBLLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

sub dnsbl_policy_deny_allow {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'dnsbl');

  my $dnsbl_domain = 'bl.spamcop.net';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_dnsbl.c' => {
        DNSBLEngine => 'on',
        DNSBLLog => $setup->{log_file},
        DNSBLDomain => $dnsbl_domain,
        DNSBLPolicy => 'deny,allow',
      },

      'mod_proxy_protocol.c' => {
        ProxyProtocolEngine => 'on',
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

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(2);

      my $client = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port, 1,
        ['TCP4', '127.0.0.2', '2.2.2.2', 111, 222]);
      $client->quit();
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

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /found record for DNS name '2\.0\.0\.127\.$dnsbl_domain'/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected DNSBLLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  test_cleanup($setup, $ex);
}

1;
