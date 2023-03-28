package ProFTPD::Tests::Config::MaxHostsPerUser;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::ProxiedFTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  maxhostsperuser_one => {
    order => ++$order,
    test_class => [qw(forking mod_proxy_protocol)],
  },

  maxhostsperuser_one_multi_conns => {
    order => ++$order,
    test_class => [qw(forking mod_proxy_protocol)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub maxhostsperuser_one {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $max_hosts = 1;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    MaxHostsPerUser => $max_hosts,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy_protocol.c' => {
        ProxyProtocolEngine => 'on',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $proxy_info = ['TCP4', '1.1.1.1', '127.0.0.1', 111, $port];

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
      sleep(1);

      # First client should be able to connect and log in...
      my $client1 = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port,
        ['TCP4', '127.0.0.1', '127.0.0.1', 12345, $port]);
      $client1->login($setup->{user}, $setup->{passwd});

      # ...but the second client should be able to connect, but not login.
      my $client2 = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port,
        $proxy_info);
      eval { $client2->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
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

sub maxhostsperuser_one_multi_conns {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'config');

  my $max_hosts = 1;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    MaxHostsPerUser => $max_hosts,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy_protocol.c' => {
        ProxyProtocolEngine => 'on',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $proxy_info = ['TCP4', '1.1.1.1', '127.0.0.1', 111, $port];

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
      sleep(1);

      # First client should be able to connect and log in...
      my $client1 = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port,
        ['TCP4', '127.0.0.1', '127.0.0.1', 12345, $port]);
      $client1->login($setup->{user}, $setup->{passwd});

      # ...but the second client should be able to connect, but not login.
      my $client2 = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port,
        $proxy_info);
      eval { $client2->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      # Even though we can't log in, we should be able to connect quite
      # a few more times

      my $clients = [];
      for (my $i = 0; $i < 10; $i++) {
        my $client = ProFTPD::TestSuite::ProxiedFTP->new('127.0.0.1', $port,
          $proxy_info);
        push(@$clients, $client);
      }

      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
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
