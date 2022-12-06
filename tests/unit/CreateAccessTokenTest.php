<?php

namespace Wiraizkandar\Jwt\Tests\unit;

use Orchestra\Testbench\TestCase;
use Wiraizkandar\Jwt\Token;
use Config;

class CreateAccessTokenTest extends TestCase
{
	public function setUp():void
	{
		parent::setUp();
		$this->setConfigs();
	}

	/**
	 * @return void
	 */
	public function test_create_access_token()
	{
		$claims['user_id'] = 12121;

		$token = new Token();

		$jwtToken = $token->createAccessToken($claims);

		$this->assertArrayHasKey('access_token',$jwtToken);
	}

	public function test_create_refresh_token()
	{
		$claims['user_id'] = 12121;

		$token = new Token();

		$jwtToken = $token->createAccessToken($claims);

		$this->assertArrayHasKey('refresh_token',$jwtToken);
	}

	public function test_check_refresh_token()
	{
		$claims['user_id'] = 12121;

		$token = new Token();

		$refreshTokenString = md5('thisisrefreshtoken');

		$verified = $token->verifyRefreshToken($refreshTokenString,$claims['user_id']);

		$this->assertFalse($verified);
	}

	/**
	 * Set default config for testing
	 */
	private function setConfigs(){
		Config::set('config.secret_key','this_is_my_secret_key');
		Config::set('config.algo','HS256');
		Config::set('config.scope_end_point_verify','http://www.example.com');
	}
}
