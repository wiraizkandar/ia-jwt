<?php

namespace Wiraizkandar\Jwt;

use Illuminate\Support\ServiceProvider;

class JwtServiceProvider extends ServiceProvider
{
	/**
	 * Bootstrap the application services.
	 */
	public function boot()
	{
		/*
		 * Optional methods to load your package assets
		 */
		// $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'ia-jwt');
		// $this->loadViewsFrom(__DIR__.'/../resources/views', 'ia-jwt');
		// $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
		// $this->loadRoutesFrom(__DIR__.'/routes.php');

		if ($this->app->runningInConsole()) {
			$this->publishes([
				__DIR__ . '/../config/jwt.php' => config_path('jwt.php'),
			], 'config');

			if (! class_exists('CreateRefreshTokenTable')) {
				$this->publishes([
					__DIR__ . '/../database/migrations/create_refresh_token_table.php' => database_path('migrations/' . date('Y_m_d_His', time()) . '_create_refresh_token_table.php'),
					// you can add any number of migrations here
				], 'migrations');
			}

			// Publishing the views.
			/*$this->publishes([
				__DIR__.'/../resources/views' => resource_path('views/vendor/ia-jwt'),
			], 'views');*/

			// Publishing assets.
			/*$this->publishes([
				__DIR__.'/../resources/assets' => public_path('vendor/ia-jwt'),
			], 'assets');*/

			// Publishing the translation files.
			/*$this->publishes([
				__DIR__.'/../resources/lang' => resource_path('lang/vendor/ia-jwt'),
			], 'lang');*/

			// Registering package commands.
			// $this->commands([]);
		}
	}

	/**
	 * Register the application services.
	 */
	public function register()
	{
		// Automatically apply the package configuration
		$this->mergeConfigFrom(__DIR__ . '/../config/jwt.php', 'jwt');

		// Register the main class to use with the facade
		$this->app->singleton('jwt', function () {
			return new Jwt;
		});
	}
}
