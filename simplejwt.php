<?php
//Example
$jwt_key=jwt_generateKey();

$jwt=generateJWT(array("user_id"=>3),3600);

print_r($jwt_key);
print_r("\n\n");
print_r($jwt);
print_r("\n\n");
print_r(validateJWT($jwt));


//Functions
function generateJWT($payload,$expire){
global $jwt_key;
$expirationTime=time()+$expire; 
$payload["exp"]=$expirationTime;
$header=jwt_atob(json_encode(array("typ"=>"JWT","alg"=>"HS256")));
$payload=jwt_atob(json_encode($payload));
$signature=hash_hmac('sha256',$header.'.'.$payload,$jwt_key,true);
$jwt=$header.'.'.$payload.'.'.jwt_atob($signature);
return $jwt;
}
function validateJWT($jwt){
global $jwt_key;
$r=array("authorized"=>false,"valid"=>false,"expired"=>false,"code"=>0,"payload"=>array());
$c=explode('.',$jwt);
$e=false;
if($jwt==""||count($c)!=3){$e=true;}
try{
list($header,$payload,$signature)=explode('.',$jwt);
$decodedPayload=jwt_btoa($payload);
$expectedSignature=hash_hmac('sha256',$header.'.'.$payload,$jwt_key,true);
$isValid=hash_equals($expectedSignature,jwt_btoa($signature));
$r["payload"]=json_decode($decodedPayload,true);
if($isValid){
$data=json_decode($decodedPayload,true);
$t=time();
if($t>$data['exp']){
$r["code"]=3;
$r["expired"]=true;
}else{
$r["code"]=1;
$r["authorized"]=true;
$r["expired"]=false;
}
$r["valid"]=true;
}else{
$r["code"]=2;
$r["expired"]=false;
}
}catch(Exception $ex){$e=true;}
if($e){
$r["code"]=4;
$r["expired"]=false;
$r["valid"]=false;
$r["authorized"]=false;
}
return $r;
}
function jwt_atob($s){
return rtrim(strtr(base64_encode($s),'+/','-_'),'=');
}
function jwt_btoa($s){
return base64_decode(strtr($s,'_-','/+'));
}
function jwt_generateKey() {
$c='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_/?0123456789';
$r='';
for($i=0;$i<43;$i++){
$r.=$c[random_int(0,strlen($c)-1)];
}
return $r;
}
?>
