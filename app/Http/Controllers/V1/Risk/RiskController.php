<?php

namespace App\Http\Controllers\V1\Risk;

use App\Http\Controllers\Controller;
use App\Models\RiskAudit;
use App\Models\RiskEvent;
use App\Models\RiskIndicator;
use App\Services\RiskService;
use Illuminate\Http\Request;

class RiskController extends Controller
{
    public function indicators(Request $request)
    {
        $query = RiskIndicator::query();
        if ($request->input('type')) $query->where('type', $request->input('type'));
        return response(['data' => $query->orderByDesc('id')->paginate($this->perPage($request))]);
    }

    public function storeIndicator(Request $request)
    {
        $rawType = $request->input('type');
        $type = is_string($rawType) ? $rawType : '';
        $rawValue = $request->input('value');
        $value = is_string($rawValue) ? $rawValue : '';
        if (!in_array($type, ['email', 'ip', 'ua'], true) || $value === '') abort(422, 'Invalid indicator');
        $this->validateValue($type, $value);
        $note = $request->input('note');
        if ($note !== null && !is_string($note)) abort(422, 'Invalid note');
        if (is_string($note) && strlen($note) > 255) abort(422, 'Note is too long');
        $indicator = (new RiskService())->addIndicator($type, $value, $note === null ? null : trim($note), null);
        return response(['data' => $indicator], 201);
    }

    public function updateIndicator(Request $request, $id)
    {
        $indicator = RiskIndicator::findOrFail($id);
        $data = $request->only(['value', 'note', 'enabled']);
        if (isset($data['value'])) {
            if (!is_string($data['value'])) abort(422, 'Invalid indicator value');
            $data['value'] = $indicator->type === 'email' ? (new RiskService())->normalizeEmail($data['value']) : trim($data['value']);
            $this->validateValue($indicator->type, $data['value']);
        }
        if (array_key_exists('note', $data)) {
            if ($data['note'] !== null && !is_string($data['note'])) abort(422, 'Invalid note');
            if (is_string($data['note']) && strlen($data['note']) > 255) abort(422, 'Note is too long');
            if (is_string($data['note'])) $data['note'] = trim($data['note']);
        }
        if (array_key_exists('enabled', $data)) {
            $enabled = filter_var($data['enabled'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            if ($enabled === null) abort(422, 'Invalid enabled flag');
            $data['enabled'] = $enabled ? 1 : 0;
        }
        $indicator->fill($data)->save();
        $riskService = new RiskService();
        $riskService->refreshEmailIndicator($indicator);
        $riskService->audit('edit', $indicator, null);
        return response(['data' => $indicator]);
    }

    public function deleteIndicator($id)
    {
        $indicator = RiskIndicator::findOrFail($id);
        return response(['data' => (new RiskService())->removeIndicator($indicator)]);
    }

    public function events(Request $request)
    {
        return response(['data' => RiskEvent::orderByDesc('last_seen_at')->paginate($this->perPage($request))]);
    }

    public function audit(Request $request)
    {
        return response(['data' => RiskAudit::orderByDesc('id')->paginate($this->perPage($request))]);
    }

    public function health()
    {
        $mixedNodes = (new RiskService())->mixedHoneypotNodes();
        return response(['data' => [
            'honeypot_group_id' => (int)env('RISK_HONEYPOT_GROUP_ID', 0),
            'api_key_configured' => (bool)env('RISK_API_KEY_HASH', ''),
            'alert_configured' => (bool)env('RISK_ALERT_CHAT_ID', ''),
            'indicators' => RiskIndicator::where('enabled', 1)->count(),
            'events_24h' => RiskEvent::where('last_seen_at', '>=', time() - 86400)->count(),
            'mixed_honeypot_nodes' => $mixedNodes,
            'warnings' => $mixedNodes ? ['mixed_honeypot_nodes'] : []
        ]]);
    }

    private function perPage(Request $request): int
    {
        return min(100, max(1, (int)$request->input('per_page', 50)));
    }

    private function validateValue(string $type, string $value): void
    {
        if (strlen($value) > 255) abort(422, 'Indicator value is too long');
        if ($type === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL)) abort(422, 'Invalid email');
        if ($type !== 'ip') return;
        [$address, $bits] = array_pad(explode('/', $value, 2), 2, null);
        $max = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 128 : 32;
        if (!filter_var($address, FILTER_VALIDATE_IP) || ($bits !== null && (!ctype_digit($bits) || (int)$bits > $max))) abort(422, 'Invalid IP or CIDR');
    }
}
