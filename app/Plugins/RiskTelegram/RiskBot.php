<?php

namespace App\Plugins\RiskTelegram;

use App\Exceptions\RiskIpAllowlistedException;
use App\Models\RiskEvent;
use App\Models\RiskIndicator;
use App\Models\User;
use App\Plugins\RiskTelegram\Commands\RiskCommand;
use App\Services\RiskService;
use App\Services\RiskSettings;
use App\Services\TelegramService;

/**
 * The risk bot: turns Telegram updates into commands and button actions, and checks who may use them.
 * Only admins whose Telegram account is bound (telegram_id) may act; commands work in private chats and the alert chat.
 */
class RiskBot
{
    private $telegram;
    private $view;
    private $botId;

    public function __construct()
    {
        $token = (string)RiskSettings::get('bot_token');
        $this->telegram = app()->makeWith(TelegramService::class, ['token' => $token]);
        $this->view = new RiskView();
        $this->botId = (int)explode(':', $token)[0];
    }

    /**
     * The commands for setMyCommands, in menu order.
     */
    public static function commandList(): array
    {
        return array_map(function (RiskCommand $command) {
            return ['command' => $command->command, 'description' => $command->description];
        }, self::commands());
    }

    public function view(): RiskView
    {
        return $this->view;
    }

    public function handleMessage(array $data): void
    {
        $parts = preg_split('/\s+/', trim((string)$data['text']));
        $name = strtolower(explode('@', (string)array_shift($parts))[0]);
        $message = (object)[
            'command' => $name,
            'args' => $parts,
            'chat_id' => (int)$data['chat']['id'],
            'message_id' => (int)($data['message_id'] ?? 0),
            'is_private' => ($data['chat']['type'] ?? '') === 'private',
            'sender_id' => (int)($data['from']['id'] ?? $data['chat']['id']),
            'reply_text' => $this->repliedText($data),
        ];
        foreach (self::commands() as $command) {
            if ($command->command !== $name && !in_array($name, $command->aliases, true)) continue;
            try {
                $admin = $command->public ? null : $this->authorize($message);
                if ($command->public || $admin) $command->handle($this, $message, $admin);
            } catch (\Throwable $e) {
                report($e);
                $this->reply($message, '处理失败，请检查服务日志');
            }
            return;
        }
    }

    public function handleCallback(array $callback): void
    {
        $id = (string)($callback['id'] ?? '');
        $message = $callback['message'] ?? null;
        if (!is_array($message) || !isset($message['chat']['id'], $message['message_id'])) return;
        $admin = $this->adminFor((int)($callback['from']['id'] ?? 0));
        if (!$admin) {
            $this->telegram->answerCallbackQuery($id, '无权限');
            return;
        }
        $context = (object)[
            'chat_id' => (int)$message['chat']['id'],
            'message_id' => (int)$message['message_id'],
            'text' => (string)($message['text'] ?? ''),
            'entities' => is_array($message['entities'] ?? null) ? $message['entities'] : [],
            'by' => $this->displayName($callback['from']),
            // Set by an action whose notice must be read before going on: shown in a dialog instead
            'alert' => false,
        ];
        try {
            $notice = $this->runCallback((string)($callback['data'] ?? ''), $context, $admin);
        } catch (\Throwable $e) {
            report($e);
            $notice = '处理失败，请检查服务日志';
        }
        // Telegram takes at most 200 characters
        $this->telegram->answerCallbackQuery($id, mb_substr($notice, 0, 200, 'UTF-8'), $context->alert);
    }

    /**
     * A field of the alert or user card that the message replies to: 'uid', 'email' or 'ip'.
     */
    public function replyField($message, string $field): ?string
    {
        $patterns = [
            'uid' => '/^uid: *(\d+)\s*$/mu',
            'email' => '/^(?:email|邮箱): *(\S+@\S+)\s*$/mu',
            'ip' => '/^ip: *([0-9A-Fa-f:.]+)\s*$/mu',
        ];
        return preg_match($patterns[$field], (string)$message->reply_text, $match) ? $match[1] : null;
    }

    public function reply($message, string $text, bool $markdown = false, array $keyboard = []): void
    {
        $this->telegram->sendMessage($message->chat_id, $text, $markdown ? 'MarkdownV2' : '', $this->markup($keyboard),
            $message->message_id ?: null);
    }

    public function replyView($message, array $view): void
    {
        $this->reply($message, $view['text'], true, $view['keyboard']);
    }

    /**
     * /add, /addip and the like: add the values as indicators of the type.
     */
    public function addIndicators($message, User $admin, string $type, array $values): void
    {
        $result = (new RiskService())->actingAs('bot', $admin->id)->addIndicators($type, $values);
        $notes = $type === 'email' && $result['added'] ? $this->usersLine('🔒 已隔离', $result['added'], true) : [];
        if ($type === 'allow_ip' && $result['invalid']) $notes[] = $this->view->escape(RiskService::ALLOW_IP_FORMAT);
        $this->reply($message, $this->view->result([
            '✅ 新增' => $result['added'], '⚠️ 已存在' => $result['existing'], '❌ 格式无效' => $result['invalid'],
            '🟢 在 IP 白名单里，没有加入' => $result['allowlisted'], '🌐 已从 IP 名单移除' => $result['disabled'],
        ], $notes), true);
    }

    /**
     * /del, /delip and the like: disable the indicators with these values.
     */
    public function removeIndicators($message, User $admin, string $type, array $values): void
    {
        $service = (new RiskService())->actingAs('bot', $admin->id);
        $deleted = $missing = [];
        foreach ($values as $rawValue) {
            $value = $service->normalizeIndicatorValue($type, $rawValue) ?? trim((string)$rawValue);
            // Also as typed: IPs added before they were stored in their standard form
            $indicator = RiskIndicator::where('type', $type)->whereIn('value', array_unique([$value, trim((string)$rawValue)]))
                ->where('enabled', 1)->first();
            if (!$indicator) {
                $missing[] = $value;
                continue;
            }
            if ($service->removeIndicator($indicator)) $deleted[] = $value;
        }
        $notes = $type === 'email' && $deleted ? $this->usersLine('🔓 已解除隔离', $deleted, false) : [];
        $this->reply($message, $this->view->result(['✅ 删除' => $deleted, '⚠️ 不存在' => $missing], $notes), true);
    }

    private function runCallback(string $data, $context, User $admin): string
    {
        // Paging buttons on messages sent before the menu existed
        if (preg_match('/^risk_(list|users|ip|ua|asn):(\d+)$/', $data, $match)) {
            $data = $match[1] === 'users' ? "r:u:{$match[2]}" : 'r:l:' . ($match[1] === 'list' ? 'email' : $match[1]) . ":{$match[2]}";
        }
        $parts = explode(':', $data);
        if ($parts[0] !== 'r') return '';
        $verb = (string)($parts[1] ?? '');
        $int = function (int $index) use ($parts) { return (int)($parts[$index] ?? 0); };
        switch ($verb) {
            case 'm': $this->edit($context, $this->view->menu()); return '';
            case 'u': $this->edit($context, $this->view->riskUsers($int(2))); return '';
            case 'e': $this->edit($context, $this->view->events($int(2))); return '';
            case 'l': $this->edit($context, $this->view->indicators((string)($parts[2] ?? ''), $int(3))); return '';
            case 'a': $this->edit($context, $this->view->audit($int(2))); return '';
            case 'h': $this->edit($context, $this->view->health()); return '';
        }
        if (in_array($verb, ['p', 'P', 'k', 'w', 'W'], true)) return $this->eventAction($verb, RiskEvent::find($int(2)), $context, $admin);
        if (!in_array($verb, ['c', 'cr', 'ue', 'i', 'r', 'I', 'R', 'x'], true)) return '';

        $card = in_array($verb, ['c', 'cr', 'ue'], true);
        $user = User::find($card ? $int(2) : $int(3));
        if (!$user) return '用户不存在';
        if ($verb === 'c') $this->edit($context, $this->view->userCard($user));
        if ($verb === 'cr') $this->send($context->chat_id, $this->view->userCard($user), $context->message_id);
        if ($verb === 'ue') $this->edit($context, $this->view->userEvents($user, (string)($parts[3] ?? 's'), $int(4)));
        if ($card) return '';
        return $this->userAction($verb, (string)($parts[2] ?? ''), $user, RiskEvent::find($int(4)), $context, $admin);
    }

    /**
     * Isolating or releasing a user from an alert ('a') or a user card ('c'): ask first, then do it.
     */
    private function userAction(string $verb, string $where, User $user, ?RiskEvent $event, $context, User $admin): string
    {
        $suffix = "{$where}:{$user->id}:" . ($event ? $event->id : '');
        $email = $this->view->shorten($user->email, 32);
        if ($verb === 'i') return $this->askToConfirm($context, "确认隔离 {$email}", "r:I:{$suffix}", "r:x:{$suffix}");
        if ($verb === 'r') return $this->askToConfirm($context, "确认解除 {$email}", "r:R:{$suffix}", "r:x:{$suffix}");

        $service = (new RiskService())->actingAs('bot', $admin->id);
        $notice = '';
        $line = '';
        if ($verb === 'I') {
            if ($this->view->isolated($user)) {
                $notice = '已经是隔离状态';
            } else {
                try {
                    $service->isolateUser($user);
                } catch (\InvalidArgumentException $e) {
                    return '邮箱格式无效，无法隔离';
                }
                [$notice, $line] = ['已隔离', '🔒 已隔离'];
            }
        } elseif ($verb === 'R') {
            if (!$this->view->isolated($user)) {
                $notice = '该用户没有被隔离';
            } else {
                $service->releaseUser($user);
                [$notice, $line] = ['已解除隔离', '🔓 已解除隔离'];
            }
        }
        $user->refresh();
        if ($where === 'c') {
            $this->edit($context, $this->view->userCard($user));
        } elseif ($line) {
            $this->appendLine($context, "{$line} · {$context->by} · " . date('m-d H:i'), $this->view->alertKeyboard($user, $event));
        } else {
            $this->editKeyboard($context, $this->view->alertKeyboard($user, $event));
        }
        return $notice;
    }

    /**
     * Buttons of an alert about one event: list its IP, allowlist it, or mark the alert handled.
     */
    private function eventAction(string $verb, ?RiskEvent $event, $context, User $admin): string
    {
        if (!$event) return '找不到这条事件';
        $user = $event->user_id ? User::find($event->user_id) : null;
        if ($verb === 'k') {
            $this->appendLine($context, "✅ 已处理 · {$context->by} · " . date('m-d H:i'), []);
            return '已标记为已处理';
        }
        if ($verb === 'p') {
            return $this->askToConfirm($context, "确认把 {$event->ip} 加入 IP 名单", "r:P:{$event->id}", "r:x:a:{$event->user_id}:{$event->id}");
        }
        $service = (new RiskService())->actingAs('bot', $admin->id);
        if ($verb === 'w' || $verb === 'W') return $this->allowEventIp($verb === 'W', $event, $user, $context, $service);
        $ip = $service->normalizeIndicatorValue('ip', $event->ip);
        if ($ip === null) return 'IP 无效';
        $indicator = RiskIndicator::where('type', 'ip')->where('value', $ip)->first();
        if ($indicator && $indicator->enabled) return '这个 IP 已在名单里';
        try {
            $service->addIndicator('ip', $ip, $user ? "来自告警（uid {$user->id}）" : '来自告警');
        } catch (RiskIpAllowlistedException $e) {
            if ($user) $this->editKeyboard($context, $this->view->alertKeyboard($user, $event));
            return "这个 IP 在 IP 白名单 {$e->entry->value} 里，不能加入 IP 名单";
        }
        $this->appendLine($context, "🌐 {$ip} 已加入 IP 名单 · {$context->by} · " . date('m-d H:i'),
            $user ? $this->view->alertKeyboard($user, $event) : []);
        return '已加入 IP 名单';
    }

    /**
     * 放行此 IP on an alert: first ask, saying what it does and how many users the IP had (many suggest a CDN or proxy
     * address), then add it to the allowlist, an IPv6 address as its /64.
     */
    private function allowEventIp(bool $confirmed, RiskEvent $event, ?User $user, $context, RiskService $service): string
    {
        $ip = (string)$event->ip;
        $range = $service->allowRangeFor($ip);
        if ($range === null) return '内网、保留地址不能加入 IP 白名单';
        $entry = $service->allowEntryFor($ip);
        if ($entry) {
            if ($user) $this->editKeyboard($context, $this->view->alertKeyboard($user, $event));
            return "这个 IP 已在 IP 白名单 {$entry->value} 里";
        }
        if (!$confirmed) {
            $users = $service->recentUserCounts([$ip])[$ip] ?? 0;
            $this->askToConfirm($context, "确认放行 {$range}", "r:W:{$event->id}", "r:x:a:{$event->user_id}:{$event->id}");
            $context->alert = true;
            return '放行 ' . $range . ($range !== $ip ? '（这个 IPv6 地址所在的 /64）' : '') .
                "：之后它命中 IP、ASN 名单不再告警，UA、邮箱名单照常。\n最近 30 天的风险事件里有 {$users} 个用户用过这个 IP，人数多时可能是 CDN 或代理的地址。";
        }
        $service->addIndicator('allow_ip', $range, $user ? "来自告警（uid {$user->id}）" : '来自告警', $disabled);
        $line = "🟢 {$range} 已加入 IP 白名单" . ($disabled ? '，停用了 IP 名单 ' . implode('、', $disabled) : '');
        $this->appendLine($context, "{$line} · {$context->by} · " . date('m-d H:i'), $user ? $this->view->alertKeyboard($user, $event) : []);
        return '已加入 IP 白名单';
    }

    private function askToConfirm($context, string $label, string $confirm, string $cancel): string
    {
        $this->editKeyboard($context, $this->view->confirmKeyboard($label, $confirm, $cancel));
        return '';
    }

    private function authorize($message): ?User
    {
        $alertChatId = (string)RiskSettings::get('alert_chat_id');
        if (!$message->is_private && (!$alertChatId || (string)$message->chat_id !== $alertChatId)) {
            $this->reply($message, '请私聊风险 Bot 执行此命令');
            return null;
        }
        $admin = $this->adminFor($message->sender_id);
        if (!$admin) $this->reply($message, '无权限');
        return $admin;
    }

    private function adminFor(int $telegramId): ?User
    {
        return $telegramId ? User::where('telegram_id', $telegramId)->where('is_admin', 1)->first() : null;
    }

    /**
     * The text of the message being replied to, if the risk bot sent it: replies take fields only from the bot's own
     * alerts and user cards, not from anything a person typed.
     */
    private function repliedText(array $data): string
    {
        $replied = $data['reply_to_message'] ?? null;
        if (!is_array($replied) || !$this->botId || (int)($replied['from']['id'] ?? 0) !== $this->botId) return '';
        return (string)($replied['text'] ?? '');
    }

    /**
     * After /add or /del of emails: which users were isolated or released by it.
     */
    private function usersLine(string $label, array $emails, bool $isolated): array
    {
        $users = User::whereIn('email', $emails)->where('risk_status', $isolated ? RiskService::STATUS_RISK : RiskService::STATUS_NONE)
            ->get(['id', 'email']);
        if (!$users->count()) return [];
        return [$label . ' ' . $users->count() . " 个用户:\n" . $users->map(function (User $user) {
            return '• uid ' . $this->view->code($user->id) . ' ' . $this->view->code($user->email);
        })->implode("\n")];
    }

    private function displayName(array $from): string
    {
        if (!empty($from['username'])) return '@' . $from['username'];
        $name = trim(($from['first_name'] ?? '') . ' ' . ($from['last_name'] ?? ''));
        return $name !== '' ? $name : 'uid ' . ($from['id'] ?? '?');
    }

    private function send(int $chatId, array $view, ?int $replyTo = null): void
    {
        $this->telegram->sendMessage($chatId, $view['text'], 'MarkdownV2', $this->markup($view['keyboard']), $replyTo);
    }

    /**
     * Replace the message with a view; if Telegram refuses (e.g. the message is too old), send it as a new message.
     */
    private function edit($context, array $view): void
    {
        try {
            $this->telegram->editMessageText($context->chat_id, $context->message_id, $view['text'], 'MarkdownV2',
                ['inline_keyboard' => $view['keyboard']]);
        } catch (\Throwable $e) {
            if (strpos($e->getMessage(), 'message is not modified') !== false) return;
            $this->send($context->chat_id, $view, $context->message_id);
        }
    }

    private function editKeyboard($context, array $keyboard): void
    {
        try {
            $this->telegram->editMessageReplyMarkup($context->chat_id, $context->message_id, ['inline_keyboard' => $keyboard]);
        } catch (\Throwable $e) {
            if (strpos($e->getMessage(), 'message is not modified') === false) throw $e;
        }
    }

    /**
     * Add a line to the end of the message, keeping its formatting (entities), and replace its buttons.
     */
    private function appendLine($context, string $line, array $keyboard): void
    {
        try {
            $this->telegram->editMessageText($context->chat_id, $context->message_id, $context->text . "\n\n" . $line, '',
                ['inline_keyboard' => $keyboard], $context->entities);
        } catch (\Throwable $e) {
            $this->telegram->sendMessage($context->chat_id, $line, '', [], $context->message_id);
        }
    }

    private function markup(array $keyboard): array
    {
        return $keyboard ? ['inline_keyboard' => $keyboard] : [];
    }

    /**
     * @return RiskCommand[] in menu order
     */
    private static function commands(): array
    {
        $commands = [];
        foreach (glob(__DIR__ . '/Commands/*.php') as $file) {
            $class = __NAMESPACE__ . '\\Commands\\' . basename($file, '.php');
            if (!is_subclass_of($class, RiskCommand::class) || (new \ReflectionClass($class))->isAbstract()) continue;
            $commands[] = new $class();
        }
        usort($commands, function (RiskCommand $a, RiskCommand $b) { return $a->sort <=> $b->sort; });
        return $commands;
    }
}
