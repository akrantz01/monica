<?php

namespace App\Auth\Socialite;

use Illuminate\Support\Arr;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;

class OpenIDProvider extends AbstractProvider implements ProviderInterface
{
    protected $scopes = [
        'openid',
        'profile',
        'email',
    ];

    protected $scopeSeparator = ' ';

    protected $issuer;

    protected $authUrl;

    protected $tokenUrl;

    protected $userInfoUrl;

    /**
     * Pull the provider configuration from the discovery URL
     *
     * @param string $url
     * @return $this
     */
    public function discover(string $url)
    {
        $response = $this->getHttpClient()->get($url);
        $body = json_decode($response->getBody(), true);

        $this->issuer = $body['issuer'];
        $this->authUrl = $body['authorization_endpoint'];
        $this->tokenUrl = $body['token_endpoint'];
        $this->userInfoUrl = $body['userinfo_endpoint'];

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->authUrl, $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->tokenUrl;
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->userInfoUrl, [
            'headers' => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return Arr::add(parent::getTokenFields($code), 'grant_type', 'authorization_code');
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'email' => $user['email'],
            'email_verified' => $user['email_verified'] ?? false,
            'given_name' => $user['given_name'] ?? null,
            'family_name' => $user['family_name'] ?? null,
            'name' => $user['name'] ?? null,
            'nickname' => $user['nickname'] ?? null,
        ]);
    }
}
