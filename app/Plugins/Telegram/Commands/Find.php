<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\User;
class Find extends RiskCommand { public $command='/find'; public $description='按邮箱查询用户状态'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $u=User::where('email',$message->args[0]??'')->first(); $this->sendMarkdown($message->chat_id,$u?'uid: '.$this->markdownCode((int)$u->id)."\nrisk: ".(int)$u->risk_status:'未找到');} }
