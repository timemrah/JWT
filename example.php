<?php
require 'JWT.php';




echo "<h1>CREATE JWT</h1>";
$jwtCreate = new JWT('mc.2{aC?Ex_Tr4*,se=rFF', 'HS256');

if($jwtCreate->isError()){
    echo "<h3>ERRORS</h3><pre>".print_r($jwtCreate->getErrors(), true)."</pre>";
    exit();
}

$jwtCreate->setExp('+1 day');
$jwtCreate->setPayload('uid', 142);
$jwtCreate->setPayload('dep', 'bilgiislem');
$jwtCreate->setPayload('lvl', 9);
$jwtCreate->setAud($_SERVER['HTTP_HOST']);
$jwtCreate->setIss($_SERVER['HTTP_HOST']);
$token = $jwtCreate->createToken();

echo "<h3>TOKEN</h3>$token";
echo "<h3>HEADER</h3><pre>".print_r($jwtCreate->getAllHeader(), true)."</pre>";
echo "<h3>PAYLOAD</h3><pre>".print_r($jwtCreate->getAllPayload(), true)."</pre>";
echo "<h3>ERRORS</h3><pre>".print_r($jwtCreate->getErrors(), true)."</pre>";




//----------------------------------------------------------------------------------------




echo "<h1>WELCOME JWT</h1>";
$jwtWelcome = new JWT('mc.2{aC?Ex_Tr4*,se=rFF');
$jwtWelcome->setToken('eyJhbGdvIjoiSFMyNTYiLCJ0eXBlIjoiSldUIn0.eyJleHAiOjE2Nzk1MjcxODIsInVpZCI6IjE0MiIsImRlcCI6ImJpbGdpaXNsZW0iLCJsdmwiOiI5IiwiaWF0IjoxNjc5NDQwNzgyfQ.sqhsdCNNo10z77Q35Hzri-iOxyvZZxe5J7QFRw6rg4A');
$verifyResult = $jwtWelcome->verifyToken();

echo "<h3>VERIFY RESULT</h3>";
var_dump($verifyResult);
echo "<h3>HEADER</h3><pre>".print_r($jwtWelcome->getAllHeader(), true)."</pre>";
echo "<h3>PAYLOAD</h3><pre>".print_r($jwtWelcome->getAllPayload(), true)."</pre>";
echo "<h3>ERRORS</h3><pre>".print_r($jwtWelcome->getErrors(), true)."</pre>";
