package ProFTPD::TestSuite::ProxiedFTP;

use strict;
use vars qw(@ISA);

use Carp;
use Net::FTP;

@ISA = qw(Net::FTP);

my $proxy_info = undef;

sub new {
  my $class = shift;
  my ($addr, $port, $proxy, $timeout) = @_;
  $timeout = 5 unless defined($timeout);
  my $debug = undef;

  $proxy_info = $proxy;

  if ($ENV{TEST_VERBOSE}) {
    $debug = 10;
  }

  my $self = $class->SUPER::new($addr,
    Port => $port,
    Timeout => $timeout,
    Debug => $debug,
  );

  unless ($self) {
    croak($@);
  }

  return $self;
}

# Override response() from Net::Cmd to trigger sending the PROXY command
sub response {
  my $self = shift;

  if (defined($proxy_info)) {
    if (ref($proxy_info)) {
      my ($proto, $src_addr, $dst_addr, $src_port, $dst_port) = @$proxy_info;
      $self->command("PROXY", $proto, $src_addr,  $dst_addr, $src_port, $dst_port);

    } else {
      $self->rawdatasend($proxy_info);
    }

    $proxy_info = undef;
  }

  $self->SUPER::response();
}

sub login {
  my $self = shift;

  unless ($self->SUPER::login(@_)) {
    croak("Failed to login: " . $self->code . " " . $self->message);
  }

  return 1;
}
1;
