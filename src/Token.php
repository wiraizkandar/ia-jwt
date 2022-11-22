<?php

namespace Wiraizkandar\Jwt;

use Ramsey\Uuid\Uuid;

class Token
{
	/**
	 * Create JWT access token
	 * @return string
	 */
	public function createAccessToken(array $payload) : array
	{

		return [
			"access_token" => '',
			"refresh_token" => $this->createRefreshToken()
		];
	}

	/**
	 * @return bool
	 */
	private function createRefreshToken(): string {
		return Uuid::uuid4();
	}
}