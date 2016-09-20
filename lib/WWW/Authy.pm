package WWW::Authy;
# ABSTRACT: Easy access to the already so easy Authy API

=head1 SYNOPSIS

  my $authy = WWW::Authy->new($authy_api_key);

  # email, cellphone, country code (optional)
  my $id = $authy->new_user('email@universe.org','555-123-2345','1');

  $authy->verify($id,$token) or print (Dumper $authy->errors);

  $authy->sms($id); # send sms for token

=cut

use MooX qw(
	+LWP::UserAgent
	+HTTP::Request::Common
	+URI
	+URI::QueryParam
	+JSON
);

use Scalar::Util qw(reftype);

=head1 DESCRIPTION

This library gives an easy way to access the API of L<Authy|https://www.authy.com/> 2-factor authentification system.

=cut

use Carp qw( croak );

our $VERSION ||= '0.000';

=attr api_key

API Key for the account given on the Account Settings

=cut

has api_key => (
	is => 'ro',
	required => 1,
);

=attr sandbox

Use the sandbox instead of the live system. This is off by default.

=cut

has sandbox => (
	is => 'ro',
	lazy => 1,
	builder => 1,
);

sub _build_sandbox { 0 }

=attr response

Gives back the full (decoded) JSON response to the last request.

=cut

has response => (
	is => 'rw',
	predicate => 1,
	clearer => 1,
);

=cut

=attr error

Gives back the error of the last request, if any given.

=cut

has errors => (
	is => 'rw',
	predicate => 1,
	clearer => 1,
);

=attr base_uri

Base of the URL of the Authy API, this is B<https://api.authy.com> without
sandbox mode, and B<http://sandbox-api.authy.com>, when the sandbox is
activated.

=cut

has base_uri => (
	is => 'ro',
	lazy => 1,
	builder => 1,
);

sub _build_base_uri {
	shift->sandbox
		? 'http://sandbox-api.authy.com'
		: 'https://api.authy.com'
}

=attr useragent

L<LWP::UserAgent> object used for the HTTP requests.

=cut

has useragent => (
	is => 'ro',
	lazy => 1,
	builder => 1,
);

sub _build_useragent {
	my ( $self ) = @_;
	LWP::UserAgent->new(
		default_headers => HTTP::Headers->new(
			'X-Authy-API-Key' => $self->api_key,
		),
		agent => $self->useragent_agent,
		$self->has_useragent_timeout ? (timeout => $self->useragent_timeout) : (),
	);
}

=attr useragent_agent

The user agent string used for the L</useragent> object.

=cut

has useragent_agent => (
	is => 'ro',
	lazy => 1,
	builder => 1,
);

sub _build_useragent_agent { (ref $_[0] ? ref $_[0] : $_[0]).'/'.$VERSION }

=attr useragent_timeout

The timeout value in seconds used for the L</useragent> object, defaults to default value of
L<LWP::UserAgent>.

=cut

has useragent_timeout => (
	is => 'ro',
	predicate => 'has_useragent_timeout',
);

=attr json

L<JSON> object used for JSON decoding.

=cut

has json => (
	is => 'ro',
	lazy => 1,
	builder => 1,
);

sub _build_json {
	my $json = JSON->new;
	$json->allow_nonref;
	return $json;
}

#############################################################################################################

sub BUILDARGS {
	my ( $class, @args ) = @_;
	unshift @args, "api_key" if @args % 2 && ref $args[0] ne 'HASH';
	return { @args };
}

sub request {
	my ($self, $req) = @_;
	my $response = $self->useragent->request($req);

	if ($response->is_success) {
		my $decoded = eval { $self->json->decode($response->content) };
		$self->response($decoded);
	}

	return $response;
}

sub make_url {
	my ( $self, @args ) = @_;
	my $url = join('/',$self->base_uri,'protected','json',@args);
	return URI->new($url);
}

sub parse_args {
	my ($self, $args, $param_names) = @_;

	if (ref $args->[0] and reftype($args->[0]) eq 'HASH') {
		return %{ $args->[0] };
	}

	my %args;
	@args{ @$param_names } = @$args;

	return %args;
}

sub clear_state {
	my $self = shift;
	$self->clear_errors;
	$self->clear_response;
}

sub handle_response {
	my ( $self, $response ) = @_;

	my $data = $self->json->decode($response->content);
	$self->response($data);

	if ($response->is_success) {
		return 1;
	} else {
		$self->errors($data->{errors});
		return 0;
	}
}

sub new_user_request {
	my $self = shift;
	my %args = $self->parse_args(\@_, [qw(email cellphone country_code send_install_link)]);

	my $uri = $self->make_url('users','new');
	my @post = (
		'user[email]'        => $args{email},
		'user[cellphone]'    => $args{cellphone},
		'user[country_code]' => $args{country_code} || 1,
	);

	push @post, 'send_install_link_via_sms' => $args{send_install_link} 
		if defined $args{send_install_link};

	return POST($uri->as_string, [ @post ]);
}

=method new_user

Takes the email, the cellphone number and optional the country code as
parameters and gives back the id for this user. Authy will generate the
user if he doesn't exist (verified by cellphone number), on a matching
entry it just gives back the existing user id.

Returns the new user id for success, and 0 for failure.

=cut

sub new_user {
	my $self = shift;
	$self->clear_state;
	my $response = $self->request($self->new_user_request(@_));
	my $data = $self->json->decode($response->content);
	if ($response->is_success) {
		return $data->{user}->{id};
	} else {
		$self->errors($data->{errors});
		return 0;
	}
}

sub verify_request {
	my ( $self, $id, $token ) = @_;
	my $uri = $self->make_url('verify',$token,$id);
	return GET($uri->as_string);
}

=method verify

Verifies the first parameter as user id against the second parameter the token.
It gives back a true or a false value, it still could be another error then an
invalid token, so far this module doesnt differ.

=cut

sub verify {
	my $self = shift;
	$self->clear_errors;
	my $response = $self->useragent->request($self->verify_request(@_));
	if ($response->is_success) {
		return 1;
	} else {
		my $data = $self->json->decode($response->content);
		$self->errors($data->{errors});
		return 0;
	}
}

sub sms_request {
	my ( $self, $id ) = @_;
	my $uri = $self->make_url('sms',$id);
	return GET($uri->as_string);
}

=method sms

Send a SMS to the given user id. Please be aware that this may produce cost.
See the pricing on L<http://www.authy.com/pricing/> for more informations.

=cut

sub sms {
	my $self = shift;
	$self->clear_errors;
	my $response = $self->useragent->request($self->sms_request(@_));
	if ($response->is_success) {
		return 1;
	} else {
		my $data = $self->json->decode($response->content);
		$self->errors($data->{errors});
		return 0;
	}
}

1;

=head1 SUPPORT

IRC

  Join #duckduckgo on irc.freenode.net. Highlight Getty for fast reaction :).

Repository

  http://github.com/Getty/p5-www-authy
  Pull request and additional contributors are welcome
 
Issue Tracker

  http://github.com/Getty/p5-www-authy/issues

