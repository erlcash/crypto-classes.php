<?php

class SymCryptKey
{
	const CIPHER = MCRYPT_RIJNDAEL_256;
	const MODE = MCRYPT_MODE_CBC;
	
	private $iv = null;
	private $key = null;
	
	public function __construct ($key)
	{
		$iv_size = mcrypt_get_iv_size (self::CIPHER, self::MODE);
		
		$this->iv = mcrypt_create_iv ($iv_size, MCRYPT_DEV_URANDOM);
		$this->key = $key;
	}
	
	public function getKey ()
	{
		return $this->key;
	}
	
	public function getIv ()
	{
		return $this->iv;
	}
};

class SymCrypt
{
	public static function encrypt ($content, SymCryptKey $key)
	{
		$encrypted_data = mcrypt_encrypt ($key::CIPHER, $key->getKey (), $content, $key::MODE, $key->getIv ());
		
		return bin2hex ($encrypted_data);
	}
	
	public static function decrypt ($content, SymCryptKey $key)
	{
		$content = pack ("H*" , $content);
		
		$decrypted_data = mcrypt_decrypt ($key::CIPHER, $key->getKey (), $content, $key::MODE, $key->getIv ());
		
		return $decrypted_data;
	}
};

$key = new SymCryptKey ("testing123");

$message = "hello world";
$message_encrypted = null;
$message_decrypted = null;

$message_encrypted = SymCrypt::encrypt ($message, $key);
$message_decrypted = SymCrypt::decrypt ($message_encrypted, $key);

echo "encrypted: $message_encrypted\n";
echo "decrypted: $message_decrypted\n";

?>
