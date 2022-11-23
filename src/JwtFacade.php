<?php

namespace Wiraizkandar\Jwt;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Wiraizkandar\IaJwt\Skeleton\SkeletonClass
 */
class JwtFacade extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'jwt';
    }
}
