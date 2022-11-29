<?php

namespace Wiraizkandar\Jwt\Tests\unit;

use Orchestra\Testbench\TestCase;
use Wiraizkandar\Jwt\Http\Middleware\CheckScopes;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Config;

class MiddlewareTest extends TestCase
{
	public function setUp():void
	{
		parent::setUp();
		$this->setConfigs();
	}

	/**
	 * @return void
	 */
	public function test_scope_verification_success(): void
	{
		$scope = 'User.Create';
		$request = new Request;
		$middleware = new CheckScopes;
		$payload = [
			"user_id" => 123
		];

		$jwtToken = JWT::encode($payload, config('config.secret_key'), config('config.algo'));

		/** set bearer token */
		$request->headers->set('Authorization','Bearer '.$jwtToken);

		$response = $middleware->handle($request, function ($request) {}, $scope);

		$this->assertEquals($response, null);

	}

	public function test_scope_verification_failed(): void
	{
		$scope = 'User.Create';
		$request = new Request;
		$middleware = new CheckScopes;
		Config::set('config.scope_end_point_verify','https://www.wiraizkandar.com');

		$payload = [
			"user_id" => 123
		];

		$jwtToken = JWT::encode($payload, config('config.secret_key'), config('config.algo'));

		/** set bearer token */
		$request->headers->set('Authorization','Bearer '.$jwtToken);

		$response = $middleware->handle($request, function ($request) {}, $scope);

		$this->assertEquals($response->status(), 403);

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
