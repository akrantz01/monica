<?php

namespace App\Auth\Socialite;

use InvalidArgumentException;
use \Laravel\Socialite\SocialiteManager as Manager;
use Laravel\Socialite\Two\GoogleProvider;

class SocialiteManager extends Manager
{
    protected $allowedDrivers = [
        'google',
        'oidc',
    ];

    protected function createDriver($driver)
    {
        if (in_array($driver, $this->allowedDrivers)) {
            return parent::createDriver($driver);
        }

        throw new InvalidArgumentException("Driver [$driver] not supported.");
    }

    /**
     * Create an instance of the specified driver.
     *
     * @return \Laravel\Socialite\Two\AbstractProvider
     */
    protected function createOidcDriver()
    {
        $config = $this->config->get('oauth.oidc');

        return $this->buildProvider(
            OpenIDProvider::class, $config
        )->discover($config['discovery_url']);
    }

    /**
     * Create an instance of the specified driver.
     *
     * @return \Laravel\Socialite\Two\AbstractProvider
     */
    protected function createGoogleDriver()
    {
        $config = $this->config->get('oauth.google');

        return $this->buildProvider(
            GoogleProvider::class, $config
        );
    }
}
