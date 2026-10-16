<?php
namespace App\Http\Routes\V1;

use Illuminate\Contracts\Routing\Registrar;

/**
 * The admin panel's risk-control pages. Kept apart from AdminRoute (upstream's file) so upstream changes apply cleanly;
 * the paths stay under /risk so nginx sends them to webman like the other admin requests.
 */
class RiskAdminRoute
{
    public function map(Registrar $router)
    {
        $router->group([
            'prefix' => config('v2board.secure_path', config('v2board.frontend_admin_path', hash('crc32b', config('app.key')))) . '/risk',
            'middleware' => ['admin', 'log'],
        ], function ($router) {
            $router->get('/overview', 'V1\\Admin\\RiskController@overview');
            $router->get('/setting/fetch', 'V1\\Admin\\RiskController@settingFetch');
            $router->post('/setting/save', 'V1\\Admin\\RiskController@settingSave');
            $router->get('/indicator/fetch', 'V1\\Admin\\RiskController@indicatorFetch');
            $router->post('/indicator/save', 'V1\\Admin\\RiskController@indicatorSave');
            $router->post('/indicator/update', 'V1\\Admin\\RiskController@indicatorUpdate');
            $router->post('/indicator/drop', 'V1\\Admin\\RiskController@indicatorDrop');
            $router->get('/user/fetch', 'V1\\Admin\\RiskController@userFetch');
            $router->post('/user/isolate', 'V1\\Admin\\RiskController@userIsolate');
            $router->post('/user/release', 'V1\\Admin\\RiskController@userRelease');
            $router->get('/event/fetch', 'V1\\Admin\\RiskController@eventFetch');
            $router->get('/access/fetch', 'V1\\Admin\\RiskController@accessFetch');
            $router->get('/access/stats', 'V1\\Admin\\RiskController@accessStats');
            $router->get('/node/auto', 'V1\\Admin\\RiskController@nodeAuto');
            $router->get('/audit/fetch', 'V1\\Admin\\RiskController@auditFetch');
        });
    }
}
