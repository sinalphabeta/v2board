<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
use App\Services\RiskService;
class DelUa extends RiskCommand { public $command='/delua'; public $description='删除 UA 风险名单'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $i=RiskIndicator::where('type','ua')->where('value',$message->args[0]??'')->first(); if($i)(new RiskService())->removeIndicator($i,$this->actorId); $this->telegramService->sendMessage($message->chat_id,'已删除');} }
