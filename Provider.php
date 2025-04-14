<?php

namespace Byancode\SocialiteKick;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use ParagonIE\ConstantTime\Base64UrlSafe;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'KICK';

    protected $scopeSeparator = ' ';

    protected $scopes = [
        'user:read',
    ];

    protected $user;

    protected function generateCodeChallenge(): array
    {
        $codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = Base64UrlSafe::encodeUnpadded(hash('sha256', $codeVerifier, true));

        return ['verifier' => $codeVerifier, 'challenge' => $codeChallenge];
    }

    protected function getAuthUrl($state): string
    {
        $codeData = $this->generateCodeChallenge();
        \session(['oauth_code_verifier' => $codeData['verifier']]);

        $fields = [
            'client_id'             => $this->clientId,
            'state'                 => $state,
            'response_type'         => 'code',
            'scope'                 => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'redirect_uri'          => $this->redirectUrl,
            'code_challenge'        => $codeData['challenge'],
            'code_challenge_method' => 'S256',
        ];

        $fields = array_merge($fields, $this->parameters);

        return 'https://id.kick.com/oauth/authorize?' . http_build_query($fields);
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $token = Arr::get($response, 'access_token');

        $this->user = $this->mapUserToObject(
            $this->getUserByToken($token)
        );

        return $this->user->setToken($token)
            ->setExpiresIn(Arr::get($response, 'expiry'))
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setApprovedScopes(explode($this->scopeSeparator, Arr::get($response, 'scope', '')));
    }

    public function getTokenUrl()
    {
        return 'https://id.kick.com/oauth/token';
    }

    protected function getTokenFields($code)
    {
        $codeVerifier = \session('oauth_code_verifier');
        \session()->forget('oauth_code_verifier');

        return [
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUrl,
            'code_verifier' => $codeVerifier,
            'code'          => $code,
        ];
    }

    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get('https://api.kick.com/public/v1/users', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer ' . $token,
            ],
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    protected function mapUserToObject($user)
    {
        $user = $user['data'][0] ?? [];

        return (new User)->setRaw($user)->map([
            'id'       => $user['user_id'] ?? null,
            'nickname' => $user['name'] ?? null,
            'name'     => $user['name'] ?? null,
            'avatar'   => $user['profile_picture'] ?? null,
        ]);
    }

    protected function getTokenHeaders($code)
    {
        return [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];
    }
}
