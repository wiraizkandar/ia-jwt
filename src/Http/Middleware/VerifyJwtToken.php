<?php

namespace Wiraizkandar\Jwt\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;

class VerifyJwtToken
{

	public function handle($request, Closure $next)
	{
		try {

			$jwtToken = $this->bearerToken();

			$secretKey = $this->getKey();

			$algo = $this->getAlgo();

			JWT::decode($jwtToken, new Key($secretKey, $algo));

		} catch (InvalidArgumentException $e) {
			// provided key/key-array is empty or malformed.
			return response()->json(['status' => 'Token key Invalid'],403);
		} catch (DomainException $e) {
			// provided algorithm is unsupported OR
			// provided key is invalid OR
			// unknown error thrown in openSSL or libsodium OR
			// libsodium is required but not available.
			return response()->json(['status' => 'Token domain Invalid'],403);
		} catch (SignatureInvalidException $e) {
			// provided JWT signature verification failed.
			return response()->json(['status' => 'Token signature Invalid'],403);

		} catch (BeforeValidException $e) {
			// provided JWT is trying to be used before "nbf" claim OR
			// provided JWT is trying to be used before "iat" claim.
			return response()->json(['status' => 'Token nbf/iat Invalid'],403);
		} catch (ExpiredException $e) {
			// provided JWT is trying to be used after "exp" claim.
			return response()->json(['status' => 'Token is expired'],403);
		} catch (UnexpectedValueException $e) {
			// provided JWT is malformed OR
			// provided JWT is missing an algorithm / using an unsupported algorithm OR
			// provided JWT algorithm does not match provided key OR
			// provided key ID in key/key-array is empty or invalid.
			return response()->json(['status' => 'Token in unexpected invalid'],403);
		}
		return $next($request);
	}

	/**
	 * Get the bearer token from the request headers.
	 *
	 * @return string|null
	 */
	private function bearerToken()
	{
		$header = $this->header('Authorization', '');
		if (Str::startsWith($header, 'Bearer ')) {
			return Str::substr($header, 7);
		}
		return null;
	}

	/**
	 * Get the secret key
	 *
	 * @return string|null
	 */
	private function getKey(): string
	{
		return config('secret_key');
	}

	/**
	 * Get the algo token
	 *
	 * @return string
	 */
	private function getAlgo(): string
	{
		return config('algo');
	}
}