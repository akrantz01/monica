<?php

return [
    /*
    |--------------------------------------------------------------------------
    | OAuth Login
    |--------------------------------------------------------------------------
    |
    | Enables login with 3rd party authentication providers
    |
    */

    'enable' => (bool) env('ENABLE_OAUTH', false),

    /*
    |--------------------------------------------------------------------------
    | Create Users
    |--------------------------------------------------------------------------
    |
    | Automatically create users if they do not already exist on first sign-in.
    |
    */

    'create_users' => (bool) env('OAUTH_CREATE_USERS', false),

    /*
    |--------------------------------------------------------------------------
    | Default Socialite Providers
    |--------------------------------------------------------------------------
    |
    | A selection of the default providers supported by Laravel Socialite that
    | were verified to work with Monica.
    |
    | * client_id: the client ID generated by the provider
    | * client_secret: the client secret generated by the provider
    | * redirect: the URL for the provider to redirect back to
    |
    */

    'google' => [
        'client_id' => env('GOOGLE_CLIENT_ID', null),
        'client_secret' => env('GOOGLE_CLIENT_SECRET', null),
        'redirect' => trim(env('APP_URL', 'http://localhost'), '/') . '/oauth/google/callback',
    ],

    /*
    |--------------------------------------------------------------------------
    | Generic OpenID Connect provider
    |--------------------------------------------------------------------------
    |
    | Use any service supporting the OpenID Connect protocol.
    |
    | * name: the name of the service to display to the user upon login
    | * client_id: the client ID generated by the provider
    | * client_secret: the client secret generated by the provider
    | * redirect: the URL for the provider to redirect back to
    | * discovery_url: the URL where the provider configuration can be found
    |
    */

    'oidc' => [
        'name' => env('OIDC_PROVIDER_NAME', 'OpenID Connect'),
        'client_id' => env('OIDC_CLIENT_ID', null),
        'client_secret' => env('OIDC_CLIENT_SECRET', null),
        'redirect' => trim(env('APP_URL', 'http://localhost'), '/') . '/oauth/oidc/callback',
        'discovery_url' => env('OIDC_DISCOVERY_URL', null),
    ],
];