<?php

namespace Wiraizkandar\Jwt;

use Ramsey\Uuid\Uuid;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Token
{
	private $algo;
	private $secretKey;

	public function __construct()
	{
		$this->algo = '';
		$this->secretKey = 'wiraizkandar';
	}

	/**
	 * Generate JWT access token
	 * @return array
	 */
	public function createAccessToken(array $claims, string $scope = '') : array {
		return [
			"access_token" => $this->buildAccessToken($claims, $scope),
			"refresh_token" => $this->createRefreshToken()
		];
	}

	/**
	 * Return uuid as refresh token
	 * @return string
	 */
	private function createRefreshToken(): string {
		return Uuid::uuid4();
	}

	/**
	 * @param array $claims
	 * @return string
	 */
	private function buildAccessToken(array $claims, string $scope): string{
		return JWT::encode(array_merge($claims,$this->reservedClaims()), $this->algo);
	}

	/**
	 * 'exp' = The client’s current date and time must be earlier than the expiration date and time listed in the exp claim.
	 * 'nbf' = The nbf claim identifies the time before which the token is not accepted for processing.
	 * 'iss' = The iss claim identifies the issuer of the JWT. This value is case-sensitive and must be a string value.
	 * 'sub' = The sub claim identifies the subject of the JWT. This value is case-sensitive and must be a string value.
	 * 'aud' = The aud claim identifies the audience that the JWT is intended for.
	 * 'iat' = The iat claim identifies the time the JWT was issued at.
	 * @return array
	 */
	private function reservedClaims(): array {
		return [
			'exp' => '',
			'nbf' => '',
			'iss' => '',
			'sub' => '',
			'aud' => '',
			'iat' => ''
		];
	}
}