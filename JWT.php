<?php



/**
 * JWT - Mehmet Emrah Tuncel - timemrah@gmail.com
 *
 * The JWT object is used for two main purposes
 * 1. Gives client side a token that can be checked in the future
 * 2.Verifies a token from the client.
 *
 * It is not recommended to work with the same instantiated object while performing these two separate operations.
 */




class JWT
{

    private string $secret = '';
    private string $algo = 'HS256';

    private string $encHeader  = '';
    private string $encPayload = '';
    private string $sign       = '';
    private string $token      = '';
    private array  $error       = [];

    private array $supportPhpCrypt = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512'
    ];

    private array $header = [];
    private array $payload = [];


    public function __construct(string $secret = null, string $algo = null){
        if($secret) $this->setSecret($secret);
        if($algo) $this->setAlgo($algo);
    }


    // SECRET :
    public function getSecret():string{ return $this->secret; }
    public function setSecret(string $secret):void{ $this->secret = $secret; }


    // ALGO :
    public function getAlgo():string{ return $this->algo; }
    public function setAlgo(string $algo):bool{

        $algo = strtoupper($algo);
        if(!$this->algorithmIsSupported($algo)){
            $this->addError('unsupportedAlgorithm', "The $algo algorithm is not supported.");
            return false;
        }

        $this->algo = $algo;
        return true;
    }


    public function createToken(?string $algo = null, ?string $secret = null):bool|string{

        if($algo)   $this->setAlgo($algo);
        if($secret) $this->setSecret($secret);
        if($this->isError()) return false;

        $this->header = [
            'algo' => $this->algo,
            'type' => 'JWT'
        ];
        $this->payload['iat'] = time();

        $this->encHeader  = $this->base64UrlEncode(json_encode($this->header));
        $this->encPayload = $this->base64UrlEncode(json_encode($this->payload));

        $signBinary = hash_hmac($this->globalAlgorithmToPhp($this->algo), "{$this->encHeader}.{$this->encPayload}", $this->secret, true);
        $this->sign = $this->base64UrlEncode($signBinary);

        return "{$this->encHeader}.{$this->encPayload}.{$this->sign}";

    }


    public function setToken(string $token):bool{

        $this->token = $token;

        $part = explode('.', $this->token);
        if(count($part) !== 3){
            $this->addError('badPartCount', 'The token data does not consist of tree part.');
            return false;
        }

        $this->encHeader  = $part[0];
        $this->encPayload = $part[1];
        $this->sign       = $part[2];


        // Header Check :
        $jsonCheckHeader = json_decode($this->base64UrlDecode($this->encHeader), true);
        if($jsonCheckHeader === NULL){
            $this->addError('headerNotJson', 'The header is not json');
        } else{
            $this->header = $jsonCheckHeader;
            if(empty($this->header['algo'])){
                $this->addError('algorithmNotDefined', 'Algorithm not defined in header.');
            }
            if(empty($this->header['type']) || $this->header['type'] !== 'JWT'){
                $this->addError('typeNotDefined', 'Type not defined in header.');
            }
        }

        // Payload Check
        $jsonCheckPayload = json_decode($this->base64UrlDecode($this->encPayload), true);
        if($jsonCheckPayload === NULL){
            $this->addError('payloadNotJson', 'The payload is not json');
        } else{
            $this->payload = $jsonCheckPayload;
            if(empty($this->payload)){
                $this->addError('payloadIsEmpty', 'Payload is empty.');
            }
        }

        // Header And Payload Error Check
        if($this->isError()) return false;

        // Sign Check
        if(!$this->sign){
            $this->addError('signIsEmpty', 'Sign is empty.');
            return false;
        }

        // Set algorithm by token
        if(!$this->setAlgo($this->header['algo'])) return false;

        return true;
    }


    public function verifyToken(string $token = null):bool{

        if($token && !$this->setToken($token)) return false;
        if(!$this->token)                      return false;
        if($this->isError())                   return false;

        $createCheckSignBinary = hash_hmac($this->globalAlgorithmToPhp($this->algo), "{$this->encHeader}.{$this->encPayload}", $this->secret, true);
        $createCheckSign       = $this->base64UrlEncode($createCheckSignBinary);

        if(!hash_equals($this->sign, $createCheckSign)){
            $this->addError('unverifiedSign', 'The signature cannot be verified with the secret key.');
            return false;
        }

        if($this->getExp() && $this->getExp() < time()){
            $this->addError('expired', 'This token has expired.');
            return false;
        }

        return true;
    }


    // GET, SET, REMOVE :
    // Header
    public function getAllHeader():array{ return $this->header; }
    public function getHeader(string $name):?string{ return $this->header[$name] ?? NULL; }
    public function setHeader(string $name, string|int $value):void{ $this->header[$name] = $value; }

    // General Payload
    public function getAllPayload():array{ return $this->payload; }
    public function getPayload(string $name = null) :?string { return $this->payload[$name] ?? NULL; }
    public function setPayload(string|int $name, string $value):void{ $this->payload[$name] = $value; }
    public function removePayload($name) :void { unset($this->payload[$name]); }

    // Iss
    public function getIss()           :string { return $this->payload['iss'] ?? ''; }
    public function setIss(string $iss):void   { $this->payload['iss'] = $iss;       }
    public function removeIss()        :void   { unset($this->payload['iss']);       }

    // Sub
    public function getSub()           :string { return $this->payload['sub'] ?? ''; }
    public function setSub(string $sub):void   { $this->payload['sub'] = $sub;       }
    public function removeSub()        :void   { unset($this->payload['sub']);       }

    // Aud
    public function getAud()           :string { return $this->payload['aud'] ?? ''; }
    public function setAud(string $aud):void   { $this->payload['aud'] = $aud;       }
    public function removeAud()        :void   { unset($this->payload['aud']);       }

    // Exp
    public function getExp()           :string { return $this->payload['exp'] ?? ''; }
    public function setExp(string|int $exp):void{ $this->payload['exp'] = $exp;      }
    public function removeExp()        :void   { unset($this->payload['exp']);       }

    // Nbf
    public function getNbf()           :string { return $this->payload['Nbf'] ?? ''; }
    public function setNbf(string $nbf):void   { $this->payload['nbf'] = $nbf;       }
    public function removeNbf()        :void   { unset($this->payload['nbf']);       }

    // Iat
    public function getIat()           :string { return $this->payload['iat'] ?? ''; }
    public function setIat(string $iat):void   { $this->payload['iat'] = $iat;       }
    public function removeIat()        :void   { unset($this->payload['iat']);       }

    // Jti
    public function getJti()           :string { return $this->payload['jti'] ?? ''; }
    public function setJti(string $jti):void   { $this->payload['jti'] = $jti;       }
    public function removeJti()        :void   { unset($this->payload['jti']);       }
    // GET, SET, REMOVE //


    // ERROR MANAGEMENT PUBLIC :
    public function isError()        :bool  { return !empty($this->error);                     }
    public function getErrors()      :array { return $this->error;                             }
    public function getError(int $i) :array { return $this->error[$i];                         }
    public function getLastError()   :array { return $this->error[$this->getErrorCount() - 1]; }
    public function getErrorCount()  :int   { return count($this->error);                      }
    // ERROR MANAGEMENT PUBLIC //


    // PRIVATE :
    private function base64UrlEncode(string $data):string{
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    private function base64UrlDecode(string $data):string{
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }


    private function addError(string $code, string $msg = ''):void{
        $this->error[] = ['code' => $code, 'msg' => $msg];
    }


    private function globalAlgorithmToPhp(string $algo):?string{
        $algo = strtoupper($algo);
        return $this->supportPhpCrypt[$algo] ?? NULL;
    }
    private function algorithmIsSupported(string $algo):bool{
        return array_key_exists($algo, $this->supportPhpCrypt);
    }

}