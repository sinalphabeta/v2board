<?php

namespace App\Http\Controllers\V1\Guest;

use App\Http\Controllers\Controller;
use App\Plugins\Telegram\Commands\RiskCommand;
use App\Services\TelegramService;
use Illuminate\Http\Request;

class RiskTelegramController extends Controller
{
    public function webhook(Request $request)
    {
        $token = (string)config('risk.bot_token', '');
        $headerSecret = (string)$request->header('X-Telegram-Bot-Api-Secret-Token', '');
        $validHeader = $token && $headerSecret && hash_equals(hash('sha256', $token), $headerSecret);
        if (!$validHeader) abort(401);
        $data = $request->input('message');
        $callback = $request->input('callback_query');
        if (is_array($callback) && !empty($callback['data']) && isset($callback['message']['chat']['id'])) {
            if (preg_match('/^risk_(list|users|ip|ua):(\\d+)$/', $callback['data'], $match)) {
                $message = (object)[
                    'command' => $match[1] === 'users' ? '/riskusers' : '/list', 'args' => [],
                    'chat_id' => $callback['message']['chat']['id'],
                    'message_id' => $callback['message']['message_id'],
                    'message_type' => 'callback', 'text' => '',
                    'is_private' => ($callback['message']['chat']['type'] ?? '') === 'private',
                    'sender_id' => $callback['from']['id'] ?? $callback['message']['chat']['id']
                ];
                $command = [
                    'users' => new \App\Plugins\Telegram\Commands\RiskUsers(),
                    'ip' => new \App\Plugins\Telegram\Commands\ListIp(),
                    'ua' => new \App\Plugins\Telegram\Commands\ListUa(),
                    'list' => new \App\Plugins\Telegram\Commands\ListCommand()
                ][$match[1]];
                $command->handleCallback($message, (string)$callback['id'], (int)$match[2]);
            }
            return;
        }
        if (!is_array($data) || empty($data['text'])) return;
        $parts = preg_split('/\s+/', trim($data['text']));
        $msg = (object)[
            'command' => explode('@', array_shift($parts))[0],
            'args' => $parts,
            'chat_id' => $data['chat']['id'],
            'message_id' => $data['message_id'],
            'message_type' => 'message',
            'text' => $data['text'],
            'is_private' => ($data['chat']['type'] ?? '') === 'private',
            'sender_id' => $data['from']['id'] ?? $data['chat']['id']
        ];
        foreach (glob(base_path('app//Plugins//Telegram//Commands') . '/*.php') as $file) {
            $class = '\\App\\Plugins\\Telegram\\Commands\\' . basename($file, '.php');
            if (!class_exists($class) || $class === RiskCommand::class || !is_subclass_of($class, RiskCommand::class)) continue;
            $instance = new $class();
            if (($instance->command ?? null) !== $msg->command) continue;
            try {
                $instance->handle($msg);
            } catch (\Throwable $e) {
                report($e);
                (new TelegramService($token))->sendMessage($msg->chat_id, '处理失败，请检查服务日志', '', [], (int)($msg->message_id ?? 0) ?: null);
            }
            return;
        }
    }
}
