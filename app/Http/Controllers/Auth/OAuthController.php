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

        if (config('oauth.create_users')) {
            $user = $this->findOrCreate($socialUser);
        } else {
            $user = User::firstWhere('email', $socialUser->getEmail());
        }

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
     * @return \App\Models\User\User
     */
    protected function findOrCreate(AbstractUser $socialUser): User
    {
        return User::where('email', $socialUser->getEmail())->firstOr(function() use ($socialUser) {
            $profile = $socialUser->user;

            /** @var User $user */
            $user = app(CreateUser::class)->execute([
                // TODO: associate with account
                'account_id' => 1,
                'first_name' => $this->retrieveFirstName($profile),
                'last_name' => $this->retrieveLastName($profile),
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

    /**
     * Retrieves the user's first name from any of the possible name fields
     *
     * @param array $user
     * @return string
     */
    protected function retrieveFirstName(array $user)
    {
        if (isset($user['given_name'])) return $user['given_name'];
        elseif (isset($user['name'])) return $this->namePart($user['name'], 1);
        elseif (isset($user['nickname'])) return $this->namePart($user['nickname'], 1);
        else return '';
    }

    /**
     * Retrieves the user's last name from any of the possible name fields
     *
     * @param array $user
     * @return string
     */
    protected function retrieveLastName(array $user)
    {
        if (isset($user['family_name'])) return $user['family_name'];
        elseif (isset($user['name'])) return $this->namePart($user['name'], 2);
        elseif (isset($user['nickname'])) return $this->namePart($user['nickname'], 2);
        else return '';
    }

    /**
     * Get the first or last part of a name. Returns an empty string if there is only a first part.
     *
     * @param string $name
     * @param int $part
     * @return string
     */
    protected function namePart(string $name, int $part)
    {
        $parts = explode(' ', $name, 1);
        if (count($parts) < $part) return '';
        else return $parts[$part - 1];
    }
}
