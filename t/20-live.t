#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use_ok('WWW::Authy');

if ($ENV{WWW_AUTHY_TEST_API_KEY_SANDBOX}) {
	my $authy = WWW::Authy->new($ENV{WWW_AUTHY_TEST_API_KEY_SANDBOX}, sandbox => 1);
	isa_ok($authy,'WWW::Authy','sandbox authy object');

	my $id = $authy->new_user('someone@universe.org','555-123-1234','1');
	ok($id,'Checking that user is generated in sandbox');
	ok($authy->verify($id,'0000000'),'Testing the cheat token of sandbox');
} else {
	note 'Not doing sandbox tests without WWW_AUTHY_TEST_API_KEY_SANDBOX';
}

if ($ENV{WWW_AUTHY_TEST_API_KEY_LIVE}
	&& $ENV{WWW_AUTHY_TEST_CELLPHONE_LIVE}
	&& $ENV{WWW_AUTHY_TEST_EMAIL_LIVE}) 
{
	my $authy = WWW::Authy->new($ENV{WWW_AUTHY_TEST_API_KEY_LIVE});
	isa_ok($authy,'WWW::Authy','authy object');

	my $id = $authy->new_user(
		$ENV{WWW_AUTHY_TEST_EMAIL_LIVE},
		$ENV{WWW_AUTHY_TEST_CELLPHONE_LIVE},
		$ENV{WWW_AUTHY_TEST_COUNTRY_CODE_LIVE}
	);
	ok($id,'Checking that user is generated in live environment');

	ok(!$authy->verify($id,'000000'),'Testing random token to fail');

	if ($ENV{WWW_AUTHY_TEST_VERIFY_INTERACTIVELY}) {
		require Term::ReadLine;
		ok $authy->sms($id), "Testing ->sms"
			or diag explain $authy->errors;

		my $term   = Term::ReadLine->new("WWW::Authy-test");
		my $prompt = "Enter code sent to $ENV{WWW_AUTHY_TEST_CELLPHONE_LIVE}: ";

		my $code = $term->readline($prompt);
		ok $authy->verify($id, $code), "Testing ->verify with real token entered by user."
			or diag explain $authy->errors;
	} else {
		note "Not doing sms+verify test without WWW_AUTHY_TEST_VERIFY_INTERACTIVELY ENV variable";
	}

	if ($ENV{WWW_AUTHY_TEST_ONETOUCH_INTERACTIVELY}) {
		require Term::ReadLine;
		my $uuid = $authy->send_approval_request({
			id => $id,
			message => "Testing WWW::Authy",
			details => {
				Test => __FILE__,
				User => scalar(getpwuid $>),
			},
		});
		ok $uuid, "Received UUID"
			or diag explain $authy->errors;

		my $status = $authy->approval_request_status($uuid);
		ok $status or diag explain $authy->errors;
		is $status, 'pending';

		my $term   = Term::ReadLine->new("WWW::Authy-test");
		my $prompt = "Please approve the request and then hit ENTER to proceed";
		$term->readline($prompt);

		is $authy->approval_request_status($uuid), 'approved';
	}

	ok $authy->user_status($id), 'Testing ->user_status'
		or diag explain $authy->errors;

	ok $authy->application_details, 'Testing ->application_details'
		or diag explain $authy->errors;

	ok $authy->application_stats, 'Testing ->application_stats'
		or diag explain $authy->errors;

	if ($ENV{WWW_AUTHY_TEST_DELETE_USER}) {
		# Don't try delete_user unless specifically asked to, since the API call 
		# to new_user doesn't tell us whether we really created it or not, and
		# we don't want to delete a "real" account that somebody wanted to keep.
		ok $authy->delete_user($id), 'Testing ->delete_user'
			or diag explain $authy->errors;
	} else {
		note "Not doing delete_user test without WWW_AUTHY_TEST_DELETE_USER ENV variable";
	}
} else {
	note 'Not doing live tests without WWW_AUTHY_TEST_API_KEY_LIVE, WWW_AUTHY_TEST_CELLPHONE_LIVE and WWW_AUTHY_TEST_EMAIL_LIVE ENV variables';
}

done_testing;
