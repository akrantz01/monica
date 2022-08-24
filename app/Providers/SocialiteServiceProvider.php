<?php

namespace App\Providers;

use App\Auth\Socialite\SocialiteManager;
use Laravel\Socialite\SocialiteServiceProvider as SocialiteProvider;

class SocialiteServiceProvider extends SocialiteProvider
{
    public function register()
    {
        $this->app->singleton(\Laravel\Socialite\Contracts\Factory::class, function ($app) {
            return new SocialiteManager($app);
        });
    }
}
