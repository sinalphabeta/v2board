<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskAudit;
class Audit extends RiskCommand { public $command='/audit'; public $description='查看最近名单操作'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $rows=RiskAudit::orderByDesc('id')->limit(10)->get()->map(function($r){return $r->action.' '.$r->type.' '.$r->value;})->implode("\n"); $this->telegramService->sendMessage($message->chat_id,$rows?:'empty');} }
