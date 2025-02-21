<?php

namespace Byancode\SocialiteKick;

use SocialiteProviders\Manager\SocialiteWasCalled;

class KickExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('kick', Provider::class);
    }
}
