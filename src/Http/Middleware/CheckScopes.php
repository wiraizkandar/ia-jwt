<?php

namespace Wiraizkandar\Jwt\Http\Middleware;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Wiraizkandar\Jwt\Http\Exception\InvalidPermissionException;
use Illuminate\Http\Request;

class CheckScopes
{
	/**
	 * Handle the incoming request.
	 *
	 * @param \Illuminate\Http\Request $request
	 * @param \Closure $next
	 * @param string $scope
	 * @return \Illuminate\Http\Response
	 */
	public function handle(Request $request, $next, string $scope = '')
	{
		try {
			/**
			 * Get request access token
			 */
			$jwtToken = $this->bearerToken($request);

			/**
			 * Get secret key
			 */
			$secretKey = $this->getKey();

			/**
			 * Get JWT encryption algo
			 */
			$algo = $this->getAlgo();

			/**
			 * Decode JWT token to get JWT claims
			 */
			$decodeToken = (array)JWT::decode($jwtToken, new Key($secretKey, $algo));

			/**
			 * Verify user has scope required for the next action
			 */

			if (isset($decodeToken['user_id'])) {
				// check scope
				if (!$this->isHasPermission($jwtToken, $decodeToken['user_id'], $scope)) {
					throw new InvalidPermissionException();
				}
			}
		} catch (InvalidArgumentException $e) {
			// provided key/key-array is empty or malformed.
			return response()->json(['status' => 'Token key Invalid'], 403);
		} catch (DomainException $e) {
			// provided algorithm is unsupported OR
			// provided key is invalid OR
			// unknown error thrown in openSSL or libsodium OR
			// libsodium is required but not available.
			return response()->json(['status' => 'Token domain Invalid'], Response::HTTP_FORBIDDEN);
		} catch (SignatureInvalidException $e) {
			// provided JWT signature verification failed.
			return response()->json(['status' => 'Token signature Invalid'], Response::HTTP_FORBIDDEN);

		} catch (BeforeValidException $e) {
			// provided JWT is trying to be used before "nbf" claim OR
			// provided JWT is trying to be used before "iat" claim.
			return response()->json(['status' => 'Token nbf/iat Invalid'], Response::HTTP_FORBIDDEN);
		} catch (ExpiredException $e) {
			// provided JWT is trying to be used after "exp" claim.
			return response()->json(['status' => 'Token is expired'], Response::HTTP_FORBIDDEN);
		} catch (UnexpectedValueException $e) {
			// provided JWT is malformed OR
			// provided JWT is missing an algorithm / using an unsupported algorithm OR
			// provided JWT algorithm does not match provided key OR
			// provided key ID in key/key-array is empty or invalid.
			return response()->json(['status' => 'Token in unexpected invalid'], Response::HTTP_FORBIDDEN);
		} catch (InvalidPermissionException $e) {
			return response()->json(['status' => 'No permission for request'], Response::HTTP_FORBIDDEN);
		}
		// return response
		return $next($request);
	}

	/**
	 * Get the bearer token from the request headers.
	 * @return string|null
	 */
	private function bearerToken(Request $request)
	{
		$header = $request->header('Authorization', '');
		if (Str::startsWith($header, 'Bearer ')) {
			return Str::substr($header, 7);
		}
		return null;
	}

	private function getKey()
	{
		return config('config.secret_key');
	}

	private function getAlgo()
	{
		return config('config.algo');
	}

	/**
	 * Description check if user has scope permission
	 */
	private function isHasPermission(string $token, int $userId, string $scope): bool
	{
		try{
			$response = Http::retry(3, 1000)
				->post(config('config.scope_end_point_verify'),
					[
						'user_id' => $userId,
						'scope' => $scope
					]
				);
			return $response->successful();

		}catch (\Exception $e){
			return false;
		}
	}
}