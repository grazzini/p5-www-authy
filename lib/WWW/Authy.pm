package WWW::Authy;
# ABSTRACT: Easy access to the already so easy Authy API

=head1 SYNOPSIS

  my $authy = WWW::Authy->new($authy_api_key);

  # email, cellphone, country code (optional), send_install_link (optional)
  my $id = $authy->new_user('email@universe.org','555-123-2345','1', '0');

  # Alternatively, with named args:
  my $id = $authy->new_user({
      email => 'email@universe.org',
      cellphone => '555-123-2345',
      country_code => '1',        # optional, default is 1 (USA)
      send_install_link => '0',   # optional, default is true
  });

  $authy->sms($id)           or print (Dumper $authy->errors);
  $authy->call($id)          or print (Dumper $authy->errors);

  $authy->verify($id,$token) or print (Dumper $authy->errors);

  $authy->delete_user($id)   or print (Dumper $authy->errors);

  $authy->register_activity({
      id      => $id,
      type    => 'reset_password',
      user_ip => $ip,
      data    => \%extra_data,
  });

  my $info       = $authy->user_status($id);
  my $app_info   = $authy->application_details;
  my $app_status = $authy->application_status;

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

use Carp qw( carp croak );

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

=attr http_response

Gives back the (raw) HTTP::Response for the last request.

=cut

has http_response => (
	is => 'rw',
	clearer => '_clear_http_response',
);

=attr json_response

Gives back the full (decoded) JSON response to the last request.

=cut

has json_response => (
	is => 'rw',
	clearer => '_clear_json_response',
);

=cut

=attr error

Gives back the error of the last request, if any given.

=cut

has errors => (
	is => 'rw',
	predicate => 1,
	clearer => '_clear_errors',
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

sub _make_request {
	my ($self, $req) = @_;

	$self->_clear_errors;
	$self->_clear_json_response;
	$self->_clear_http_response;

	my $response = $self->useragent->request($req);
	$self->http_response($response);

	# This is just a warning - we'll still attempt to process the response 
	# body, which often contains a useful error.
	unless ($response->is_success) {
		carp sprintf "[Authy] HTTP Request for %s failed: %s",
		$req->uri, $response->status_line;
	}

	if ($response->content) {
		my $content = $response->content;
		my $decoded = eval { $self->json->decode($content) };

		if ($@) {
			$self->errors({ message => "Couldn't parse response: $@" });
		}
		elsif (ref($decoded) and reftype($decoded) eq 'HASH') {
			if ($decoded->{errors}) {
				$self->errors($decoded->{errors}) 
			}
			else {
				$self->json_response($decoded);
			}
		}
		else {
			$self->errors({ message => "Invalid JSON response: $content: Not a hash reference" });
		}
	}
	elsif (!$response->is_success) {
		$self->errors({ message => "Request failed: " . $response->status_line });
	}
	else {
		$self->errors({ message => "Request failed: No response from server" });
	}
}

sub _is_success {
	my $self = shift;
	return !$self->has_errors;
}

sub _make_url {
	my ( $self, @args ) = @_;
	my $url = join('/',$self->base_uri, @args);
	return URI->new($url);
}

sub _parse_args {
	my ($self, $args, $param_names) = @_;

	if (ref $args->[0] and reftype($args->[0]) eq 'HASH') {
		return %{ $args->[0] };
	}

	my %args;
	@args{ @$param_names } = @$args;

	return %args;
}

=method new_user

Takes the email, the cellphone number and optional the country code as
parameters and gives back the id for this user. Authy will generate the
user if he doesn't exist (verified by cellphone number), on a matching
entry it just gives back the existing user id.

Returns the new user id for success, and 0 for failure.

=cut

sub _new_user_request {
	my $self = shift;
	my %args = $self->_parse_args(\@_, [qw(email cellphone country_code send_install_link)]);

	my $uri = $self->_make_url('protected/json/users/new');
	my @post = (
		'user[email]'        => $args{email},
		'user[cellphone]'    => $args{cellphone},
		'user[country_code]' => $args{country_code} || 1,
	);

	push @post, 'send_install_link_via_sms' => $args{send_install_link} 
		if defined $args{send_install_link};

	return POST($uri->as_string, [ @post ]);
}

sub new_user {
	my $self = shift;
	$self->_make_request($self->_new_user_request(@_));

	if ($self->_is_success) {
		return $self->json_response->{user}{id};
	} else {
		return 0;
	}
}

=method verify

Verifies the first parameter as user id against the second parameter the token.
It gives back a true or a false value, it still could be another error then an
invalid token, so far this module doesnt differ.

Returns 1/0 for success/failure.

=cut

sub _verify_request {
	my $self = shift;
	my %args = $self->_parse_args(\@_, [qw(id token)]);

	my $uri = $self->_make_url("protected/json/verify/$args{token}/$args{id}");
	return GET($uri->as_string);
}

sub verify {
	my $self = shift;
	$self->_make_request($self->_verify_request(@_));
	return $self->_is_success;
}

=method sms

Send a SMS to the given user id. Please be aware that this may incur fees.
See the pricing on L<http://www.authy.com/pricing/> for more information.

Optional parameters C<action>, C<action_message>, and C<force> are described
in Authy's API documentation.

  $authy->sms($id);
  $authy->sms($id, $action, $action_message, $force);
  $authy->sms({ 
      id => $id,
      action => "login",
      action_message => "Here is your login key",
      force => 'true'
  });

Returns 1/0 for success/failure.

=cut

sub _sms_or_call_request {
	my $self = shift;
	my $type = shift;

	my @params = qw(action action_message force); 
	my %args   = $self->_parse_args(\@_, [id => @params]);

	my $uri = $self->_make_url("protected/json/$type/$args{id}");

	for my $param (@params) {
		$uri->query_param( $param => $args{$param} ) 
			if defined $args{$param};
	}

	return GET($uri->as_string);
}

sub _sms_request {
	my $self = shift;
	$self->_sms_or_call_request(sms => @_);
}

sub sms {
	my $self = shift;
	$self->_make_request($self->_sms_request(@_));
	return $self->_is_success;
}

=method call

Send a token via phone call to the given user id. Please be aware that this may
incur fees. See the pricing on L<http://www.authy.com/pricing/> for more
information.

Optional parameters C<action>, C<action_message>, and C<force> are described
in Authy's API documentation.

  $authy->call($id);
  $authy->call($id, $action, $action_message, $force);
  $authy->call({ id => $id, ... });

Returns 1/0 for success/failure.

=cut

sub _call_request {
	my $self = shift;
	$self->_sms_or_call_request(call => @_);
}

sub call {
	my $self = shift;
	$self->_make_request($self->_call_request(@_));
	return $self->_is_success;
}

=method delete_user

Delete the user from Authy's database.

The parameters are C<id> and (optionally) C<ip_address>.

  $authy->delete_user($id);
  $authy->delete_user($id, $ip_address);
  $authy->delete_user({ id => $id, ... });

=cut

sub _delete_request {
	my $self = shift;
	my %args = $self->_parse_args(\@_, [qw(id user_ip)]);

	my $uri = $self->_make_url("protected/json/users/$args{id}/delete");

	my @post;
	push @post, user_ip => $args{user_ip} if $args{user_ip};

	return POST($uri->as_string, \@post);
}

sub delete_user {
	my $self = shift;
	$self->_make_request($self->_delete_request(@_));
	return $self->_is_success;
}

=method register_activity

Authy says that if you register certain types of activities (which include
"password_reset", "banned", "unbanned", "cookie_login") with them, then
they can detect certain kinds of misbehavior.

The parameters are C<id>, C<type>, C<user_ip>, and C<data>.

  $authy->register_activity($id, $type, $user_ip, $data);
  $authy->register_activity({ id => $id ... });

=cut

sub _register_activity_request {
	my $self = shift;

	my @params = qw( type user_ip data );
	my %args   = $self->_parse_args(\@_, [id => @params]);

	my $uri = $self->_make_url("protected/json/users/$args{id}/register_activity");
	my @post;

	for my $param (@params) {
		push @post, $param, $args{$param} if defined $args{$param};
	}

	return POST($uri->as_string, \@post);
}

sub register_activity {
	my $self = shift;
	$self->_make_request($self->_register_activity_request(@_));
	return $self->_is_success;
}

=method application_details

Returns some metadata Authy keeps about your application.

  my $details = $authy->application_details;
  my $details = $authy->application_details($user_ip);
  my $details = $authy->application_details({ user_ip => $user_ip });

=cut

sub _application_info_request {
	my $self = shift;
	my $type = shift;
	my %args = $self->_parse_args(\@_, [qw( user_ip )]);

	my $uri = $self->_make_url("protected/json/app/$type");
	$uri->query_param( user_ip => $args{user_ip} ) if $args{user_ip};
	return GET($uri->as_string);
}

sub _application_details_request {
	my $self = shift;
	return $self->_application_info_request('details');
}

sub application_details {
	my $self = shift;
	$self->_make_request($self->_application_details_request(@_));
	return $self->json_response;
}

=method user_status

Returns some data Authy keeps about the given user, or undef if 
the request fails.

  my $status = $authy->user_status($id);
  my $status = $authy->user_status({ id => $id });

=cut

sub _user_status_request {
	my $self = shift;
	my %args = $self->_parse_args(\@_, [qw( id user_ip )]);

	my $uri = $self->_make_url("protected/json/users/$args{id}/status");
	$uri->query_param( user_ip => $args{user_ip} ) if $args{user_ip};
	return GET($uri->as_string);
}

sub user_status {
	my $self = shift;
	$self->_make_request($self->_user_status_request(@_));
	return $self->json_response;
}

=method application_stats

Returns some usage and billing statistics about your application.

  my $stats = $authy->application_stats;
  my $stats = $authy->application_stats($user_ip);
  my $stats = $authy->application_stats({ user_ip => $user_ip });

=cut

sub _application_stats_request {
	my $self = shift;
	return $self->_application_info_request('stats');
}

sub application_stats {
	my $self = shift;
	$self->_make_request($self->_application_stats_request(@_));
	return $self->json_response;
}

=method send_approval_request(\%params)

The parameters are C<id>, C<message>, C<details>, C<hidden_details>, 
C<logos>, and C<seconds_to_expire>. These are described on the Authy website.

  $authy->send_approval_request({
      id => $user_id,
      message => "Login requested for your XYZ account",
      details => {
          foo => $foo,
          bar => $bar,
      },
      hidden_details => {
          ip_address => '127.0.0.1',
      }
      seconds_to_expire => 120,
      logos => [
          { res => 'default', url => 'http://example.com/logos/default.png' },
          { res => 'low',     url => 'http://example.com/logos/low.png' },
      ]
  });

Returns an approval request id (a UUID), or C<undef> if the request failed.

=cut

sub _send_approval_request_request {
	my $self = shift;
	my $args = shift;

	my $uri = $self->_make_url("onetouch/json/users/$args->{id}/approval_requests");

	my @post;
	for my $param (qw(message seconds_to_expire)) {
		push @post, $param, $args->{$param} if defined $args->{$param};
	}
	for my $param (qw(details hidden_details)) {
		next unless defined $args->{$param} 
			    and ref $args->{$param};

		for my $k (keys %{ $args->{$param} }) {
			# e.g. "details[Location]" => "San Francisco, CA"
			push @post, "$param\[$k]", $args->{$param}{$k};
		}
	}
	for my $logo (@{ $args->{logos} || [] }) {
		push @post, "logos[][res]" => $logo->{res};
		push @post, "logos[][url]" => $logo->{url};
	}

	return POST($uri->as_string, [ @post ]);
}

sub send_approval_request {
	my $self = shift;
	$self->_make_request($self->_send_approval_request_request(@_));
	return unless $self->_is_success;
	return $self->json_response->{approval_request}{uuid};
}

=method approval_request_status($id)

The parameter is a uuid returned from L<send_approval_request>.

Returns the request status (e.g. "pending", "approved", "denied"),
or undef on failure.

Additional response information will also be available afterwards
in C<< $authy->json_response >>.

=cut

sub _approval_request_status_request {
	my $self = shift;
	my $uuid = shift;

	my $uri = $self->_make_url('onetouch/json/approval_requests', $uuid);
	return GET($uri);
}

sub approval_request_status {
	my $self = shift;
	$self->_make_request($self->_approval_request_status_request(@_));
	return unless $self->_is_success;
	return $self->json_response->{approval_request}{status};
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

