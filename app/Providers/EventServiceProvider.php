<?php

namespace App\Providers;

use App\Models\User;
use App\Services\RiskAccessService;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Event;

class EventServiceProvider extends ServiceProvider
{
    /**
     * The event listener mappings for the application.
     *
     * @var array
     */
    protected $listen = [
    ];

    /**
     * Register any events for your application.
     *
     * @return void
     */
    public function boot()
    {
        parent::boot();

        // A reset replaced a subscription token (the risk bot, the admin panel, the user, reset:user): keep the old one
        // for the risk access log, which logs its use as old_link
        User::updated(function (User $user) {
            if ($user->wasChanged('token')) (new RiskAccessService())->rememberOldToken((string)$user->getOriginal('token'), $user);
        });
    }
}
