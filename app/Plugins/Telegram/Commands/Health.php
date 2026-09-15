<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
use App\Models\RiskEvent;
use App\Services\RiskService;
class Health extends RiskCommand { public $command='/health'; public $description='检查风险系统健康状态'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $mixed=(new RiskService())->mixedHoneypotNodes(); $text='indicators='.RiskIndicator::where('enabled',1)->count().' events24h='.RiskEvent::where('last_seen_at','>=',time()-86400)->count(); if($mixed)$text.="\n警告：混合内鬼节点 ".implode(', ',$mixed); $this->telegramService->sendMessage($message->chat_id,$text);} }
