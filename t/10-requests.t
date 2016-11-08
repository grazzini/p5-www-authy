#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use_ok('WWW::Authy');

for my $sandbox (0, 1) {
	my $authy = WWW::Authy->new('123456', sandbox => $sandbox);
	my $base  = $sandbox ? "http://sandbox-api.authy.com/protected/json" : "https://api.authy.com/protected/json";

	isa_ok($authy,'WWW::Authy','authy object');
	is($authy->useragent->default_headers->header('X-Authy-API-Key'), 123456, 'Checking API-Key header');

	subtest "new_user" => sub {
		my $request = $authy->_new_user_request('em@il','123','12','0');
		isa_ok($request,'HTTP::Request','request new user');
		is($request->uri->as_string,"$base/users/new",'Checking new user request uri');
		is($request->method,'POST','Checking new user request method');
		is($request->content,'user%5Bemail%5D=em%40il&user%5Bcellphone%5D=123&user%5Bcountry_code%5D=12&send_install_link_via_sms=0',
			'Checking new user request content');
	};

	subtest "new_user__hashref" => sub {
		my $request = $authy->_new_user_request({
			email => 'em@il',
			cellphone => '123', 
		});
		isa_ok($request,'HTTP::Request','request new user');
		is($request->uri->as_string,"$base/users/new",'Checking new user request uri');
		is($request->method,'POST','Checking new user request method');
		is($request->content,'user%5Bemail%5D=em%40il&user%5Bcellphone%5D=123&user%5Bcountry_code%5D=1',
			'Checking new user request content');
	};

	subtest "verify" => sub {
		my $request = $authy->_verify_request(1,123456);

		isa_ok($request,'HTTP::Request','request verify');
		is($request->uri->as_string,"$base/verify/123456/1",'Checking verify request uri');
		is($request->method,'GET','Checking verify request method');
		is($request->content,'','Checking verify request content');
	};

	subtest "sms" => sub {
		my $request = $authy->_sms_request('123');

		isa_ok($request,'HTTP::Request','request new user');
		is($request->uri->as_string,"$base/sms/123",'Checking sms request uri');
		is($request->method,'GET','Checking sms request method');
		is($request->content,'','Checking sms request content');
	};

	subtest "sms__extra_params" => sub {
		my $request = $authy->_sms_request('123','login','msg', 'true');

		isa_ok($request,'HTTP::Request','request sms');
		is($request->uri->as_string,"$base/sms/123?action=login&action_message=msg&force=true",'Checking sms request uri');
		is($request->method,'GET','Checking sms request method');
		is($request->content,'','Checking sms request content');
	};

	subtest "sms__extra_params_hashref" => sub {
		my $request = $authy->_sms_request({
			id => '123',
			action => 'login',
			action_message => 'msg',
			force => 'true'
		});

		isa_ok($request,'HTTP::Request','request sms');
		is($request->uri->as_string,"$base/sms/123?action=login&action_message=msg&force=true",
			'Checking sms request uri');
		is($request->method,'GET','Checking sms request method');
		is($request->content,'','Checking sms request content');
	};

	subtest "call" => sub {
		my $request = $authy->_call_request('123');

		isa_ok($request,'HTTP::Request','request password via phonecall');
		is($request->uri->as_string,"$base/call/123",'Checking call request uri');
		is($request->method,'GET','Checking call request method');
		is($request->content,'','Checking call request content');
	};

	subtest "delete" => sub {
		my $request = $authy->_delete_request('123');

		isa_ok($request,'HTTP::Request','request delete user');
		is($request->uri->as_string,"$base/users/123/delete",'Checking sms request uri');
		is($request->method,'POST','Checking delete request method');
		is($request->content,'','Checking delete request content');
	};

	subtest "delete__hashref" => sub {
		my $request = $authy->_delete_request({ id => '123', user_ip => '127.0.0.1' });

		isa_ok($request,'HTTP::Request','request delete');
		is($request->uri->as_string,"$base/users/123/delete",'Checking delete request uri');
		is($request->method,'POST','Checking delete request method');
		is($request->content,'user_ip=127.0.0.1','Checking delete request content');
	};

	subtest "register_activity" => sub {
		my $request = $authy->_register_activity_request('123','login','localhost','{}');

		isa_ok($request,'HTTP::Request','request register activity');
		is($request->uri->as_string,"$base/users/123/register_activity",
			'Checking register_activity uri');
		is($request->method,'POST','Checking register_activity request method');
		is($request->content,'type=login&user_ip=localhost&data=%7B%7D',
			'Checking register_activity request content');
	};

	subtest "register_activity__hashref" => sub {
		my $request = $authy->_register_activity_request({
			id => '123',
			type => 'login',
			user_ip => 'localhost',
			data => '{}'
		});

		isa_ok($request,'HTTP::Request','request register activity');
		is($request->uri->as_string,"$base/users/123/register_activity",
			'Checking register_activity uri');
		is($request->method,'POST','Checking register_activity request method');
		is($request->content,'type=login&user_ip=localhost&data=%7B%7D',
			'Checking register_activity request content');
	};

	subtest "application_details" => sub {
		my $request = $authy->_application_details_request;

		isa_ok($request,'HTTP::Request','request application details');
		is($request->uri->as_string,"$base/app/details",'Checking application_details uri');
		is($request->method,'GET','Checking application_details request method');
	};

	subtest "user_status" => sub {
		my $request = $authy->_user_status_request(123);

		isa_ok($request,'HTTP::Request','request user_status');
		is($request->uri->as_string,"$base/users/123/status",'Checking user_status uri');
		is($request->method,'GET','Checking user_status request method');
	};

	subtest "application_stats" => sub {
		my $request = $authy->_application_stats_request;

		isa_ok($request,'HTTP::Request','request application stats');
		is($request->uri->as_string,"$base/app/stats",'Checking application_stats uri');
		is($request->method,'GET','Checking application_stats request method');
	};
}

done_testing;
