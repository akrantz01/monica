<?php

namespace App\Http\Controllers\Auth;

use App\Helpers\RequestHelper;
use App\Http\Controllers\Controller;
use App\Jobs\SendNewUserAlert;
use App\Models\User\User;
use App\Services\User\CreateUser;
use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\RedirectsUsers;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\AbstractUser;
use Laravel\Socialite\Facades\Socialite;

class OAuthController extends Controller
{
    use RedirectsUsers;

    protected $redirectTo = '/dashboard';

    public function __construct()
    {
        $this->middleware('guest');
    }

    /**
     * Redirect the user to the OAuth provider
     *
     * @param string $driver
     * @return \Illuminate\Http\RedirectResponse
     */
    public function redirect(string $driver)
    {
        return Socialite::driver($driver)->redirect();
    }

    /**
     * Handle responses from the OAuth provider
     *
     * @param string $driver
     * @return \Illuminate\Http\RedirectResponse
     */
    public function callback(string $driver)
    {
        try {
            $socialUser = Socialite::driver($driver)->user();
        } catch (\Exception) {
            return redirect(route('loginRedirect'))->withErrors(trans('auth.oauth_failed'));
        }

        $user = $this->findOrCreate($socialUser);
        if (is_null($user)) {
            return redirect(route('loginRedirect'))->withErrors(trans('auth.oauth_create_disabled'));
        }

        $guard = Auth::guard();
        $guard->login($user);

        return redirect($this->redirectPath());
    }

    /**
     * Create a user if they do not exist
     *
     * @param \Laravel\Socialite\AbstractUser $socialUser
     * @return \App\Models\User\User|null
     */
    protected function findOrCreate(AbstractUser $socialUser): User|null
    {
        if (! config('oauth.create_users')) {
            return User::firstWhere('email', $socialUser->getEmail());
        }

        return User::where('email', $socialUser->getEmail())->firstOr(function() use ($socialUser) {
            $profile = $socialUser->user;
            $name = $this->parseNameParts($profile);

            /** @var User $user */
            $user = app(CreateUser::class)->execute([
                // TODO: associate with account
                'account_id' => 1,
                'first_name' => $name['first'],
                'last_name' => $name['last'],
                'email' => $socialUser->getEmail(),
                'ip_address' => RequestHelper::ip(),
                'locale' => $profile['locale'] ?? null,
            ]);

            if ($socialUser['email_verified']) {
                $user->markEmailAsVerified();
            }

            // send me an alert
            SendNewUserAlert::dispatch($user);

            event(new Registered($user));

            return $user;
        });
    }

    protected function parseNameParts(array $user)
    {
        if (isset($user['given_name']) && isset($user['family_name'])) {
            return [
                'first' => $user['given_name'],
                'last' => $user['last_name'],
            ];
        }

        if (isset($user['name'])) {
            return $this->parseCombinedName($user['name']);
        }

        if (isset($user['nickname'])) {
            return $this->parseCombinedName($user['nickname']);
        }

        return ['first' => '', 'last' => ''];
    }

    /**
     * Retrieve the first and last name from a space-separated full name
     *
     * @param string $name
     * @return array
     */
    protected function parseCombinedName(string $name)
    {
        $parts = explode(' ', $name, 1);

        if (count($parts) < 2) {
            return [
                'first' => $name,
                'last' => '',
            ];
        }

        return [
            'first' => $parts[0],
            'last' => $parts[1],
        ];
    }
}
