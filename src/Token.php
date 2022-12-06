<?php

namespace Wiraizkandar\Jwt;

use Firebase\JWT\Key;
use Ramsey\Uuid\Uuid;
use Firebase\JWT\JWT;
use Carbon\Carbon;
use Wiraizkandar\Jwt\BaseToken;
use Illuminate\Support\Facades\DB;

class Token extends BaseToken
{
	private $algo;
	private $secretKey;
	private $refreshTokenTable;

	public function __construct()
	{
		$this->algo = config('jwt.algo');
		$this->secretKey = config('jwt.secret_key');
		$this->refreshTokenTable = config('jwt.refresh_token_table');
	}

	/**
	 * Generate JWT access token
	 * @return array
	 */
	public function createAccessToken(array $claims, ?int $userId = null, ?string $refreshToken = null): array
	{
		if (!empty($refreshToken) && !empty($userId)) {
			/** verify refresh token to recreate new access token */
			if(!$this->verifyRefreshToken($refreshToken,$userId)){
				return [
					"message" => 'Refresh token invalid',
					"access_token" => null
				];
			}
			return [
				"access_token" => $this->buildAccessToken($claims)
			];
		}

		return [
			"access_token" => $this->buildAccessToken($claims),
			"refresh_token" => $this->createRefreshToken()
		];
	}

	/**
	 * Return uuid as refresh token
	 * @return string
	 */
	private function createRefreshToken(): string
	{
		return Uuid::uuid4();
	}

	public function verifyRefreshToken(string $refreshToken, int $userId): bool
	{
		$refToken = DB::table($this->refreshTokenTable)
			->where('user_id',$userId)
			->where('refresh_token',$refreshToken)
			->where('revoked',false)
			->first();

		if($refToken){
			return Carbon::now()->gt(Carbon::parse($refToken->expiry_date));
		}
		return false;
	}

	/**
	 * @param array $claims
	 * @return string
	 */
	private function buildAccessToken(array $claims): string
	{
		return JWT::encode(array_merge($claims, $this->reservedClaims()), $this->secretKey, $this->algo);
	}

	/**
	 * 'exp' = The client’s current date and time must be earlier than the expiration date and time listed in the exp claim.
	 * 'nbf' = The 'nbf' claim identifies the time before which the token is not accepted for processing.
	 * 'iss' = The 'iss' claim identifies the issuer of the JWT. This value is case-sensitive and must be a string value.
	 * 'sub' = The 'sub' claim identifies the subject of the JWT. This value is case-sensitive and must be a string value.
	 * 'aud' = The 'aud' claim identifies the audience that the JWT is intended for.
	 * 'iat' = The 'iat' claim identifies the time the JWT was issued at.
	 */
	private function reservedClaims(): array
	{
		return [
			'nbf' => Carbon::now()->timestamp,
			'exp' => $this->setExpiry(),
			'iss' => 'AuthenticationService',
			'sub' => 'Wira Is Awesome',
			'iat' => $this->setIssuedAt(),
		];
	}

	/**
	 * @return int
	 */
	private function setExpiry(): int
	{
		return Carbon::now()->addSeconds(config('config.expiry_duration'))->timestamp;
	}

	private function setIssuedAt(): int
	{
		return Carbon::now()->timestamp;
	}
}