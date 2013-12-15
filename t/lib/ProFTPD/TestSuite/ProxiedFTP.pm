package ProFTPD::TestSuite::ProxiedFTP;

use strict;
use vars qw(@ISA);

use Carp;
use IO::Socket::INET;
use Net::Cmd;

@ISA = qw(Net::Cmd IO::Socket::INET);

sub new {
  my $class = shift;
  my ($addr, $port, $timeout) = @_;
  $timeout = 5 unless defined($timeout);
  my $debug = undef;

  my $self = $class->SUPER::new(
    PeerHost => $addr,
    PeerPort => $port,
    Proto => 'tcp',
    Type => SOCK_STREAM,
    ReuseAddr => 1,
    Blocking => 1,
    Timeout => $timeout,
  );
  return undef unless $self;

  if ($ENV{TEST_VERBOSE}) {
    $debug = 10;
  }

  $self->debug($debug);

  bless($self, $class);
  return $self;
}

sub response_code {
  my $self = shift;
  return $self->code;
}

sub response_msg {
  my $self = shift;
  return $self->message;
}

sub send_proxy_raw {
  my $self = shift;
  my ($src_addr, $dst_addr, $src_port, $dst_port, $proto) = @_;
  $src_addr = '127.0.0.1' unless defined($src_addr);
  $dst_addr = '127.0.0.1' unless defined($dst_addr);
  $src_port = $self->sockport() unless defined($src_port);
  $dst_port = $self->sockport() unless defined($dst_port);
  $proto = 'TCP4' unless defined($proto);

  # Send PROXY message
  $self->command("PROXY", $proto, $src_addr,  $dst_addr, $src_port, $dst_port);
}

sub send_proxy {
  my $self = shift;
  $self->send_proxy_raw(@_);

  my $ex;

  unless ($self->response() == CMD_OK) {
    $self->close();
    $ex = $self->message;
    undef $self;
  }

  croak($ex) if defined($ex);
  return 1;
}

sub login {
  my $self = shift;
  my $user = shift;
  my $pass = shift;

  my $ex;

  my $ok = $self->command("USER", $user)->response();
  if ($ok == CMD_OK || $ok == CMD_MORE) {
    $ok = $self->command("PASS", $pass)->response();
    unless ($ok == CMD_OK || $ok == CMD_MORE) {
      $ex = $self->message;
    }

  } else {
    $ex = $self->message;
  }

  croak($ex) if defined($ex); 
  $ok == CMD_OK;
}

sub quit {
  my $self = shift;
  my $ok = $self->command("QUIT")->response();
  $self->close();

  unless ($ok == CMD_OK || $ok == CMD_MORE) {
    croak($self->message);
  }

  $ok == CMD_OK;
}

1;
