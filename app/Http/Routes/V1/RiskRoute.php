<?php

namespace App\Http\Routes\V1;

use Illuminate\Contracts\Routing\Registrar;

class RiskRoute
{
    public function map(Registrar $router)
    {
        $router->group(['prefix' => 'risk', 'middleware' => 'risk.api'], function ($router) {
            $router->get('/indicators', 'V1\\Risk\\RiskController@indicators');
            $router->post('/indicators', 'V1\\Risk\\RiskController@storeIndicator');
            $router->patch('/indicators/{id}', 'V1\\Risk\\RiskController@updateIndicator');
            $router->delete('/indicators/{id}', 'V1\\Risk\\RiskController@deleteIndicator');
            $router->get('/events', 'V1\\Risk\\RiskController@events');
            $router->get('/audit', 'V1\\Risk\\RiskController@audit');
            $router->get('/health', 'V1\\Risk\\RiskController@health');
        });
    }
}
