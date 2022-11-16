<?php

namespace InvolveAsiaJwt;

class RefreshToken
{
	/**
	 * Create JWT access token
	 * @return string
	 */
	public static function verifyRefreshToken(string $token)
	{
		return '';
	}

	/**
	 * @return bool
	 */
	public function createRefreshToken(string $token){
		return true;
	}
}