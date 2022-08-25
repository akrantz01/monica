<?php

namespace App\Auth\Socialite;

use InvalidArgumentException;
use \Laravel\Socialite\SocialiteManager as Manager;
use Laravel\Socialite\Two\GoogleProvider;

class SocialiteManager extends Manager
{
    // The drivers that can be used
    protected $allowedDrivers = [
        'google',
        'oidc',
    ];

    /**
     * {@inheritdoc}
     */
    protected function createDriver($driver)
    {
        if (in_array($driver, $this->allowedDrivers)) {
            return parent::createDriver($driver);
        }

        throw new InvalidArgumentException("Driver [$driver] not supported.");
    }

    /**
     * Create an instance of the OpenID Connect driver.
     *
     * @return \Laravel\Socialite\Two\AbstractProvider
     */
    protected function createOidcDriver()
    {
        $config = $this->config->get('oauth.oidc');

        $provider = $this->buildProvider(OpenIDProvider::class, $config);
        $provider->discover($config['discovery_url']);

        return $provider;
    }

    /**
     * Create an instance of the Google driver.
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
