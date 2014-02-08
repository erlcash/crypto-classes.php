<?php

class AsymCryptKey
{
	const PKEY_BITS = 2048;
	const PKEY_TYPE = OPENSSL_KEYTYPE_RSA;
	
	private $public_key = null;
	private $private_key = null;
	
	public function __construct ()
	{
		// nothing todo
	}
	
	public function import ($public_key, $private_key = null)
	{
		$this->public_key = $public_key;
		$this->private_key = $private_key;
	}
	
	public function setPublicKey ($public_key)
	{
		$this->public_key = $public_key;
	}
	
	public function setPrivateKey ($private_key)
	{
		$this->private_key = $private_key;
	}
	
	public function generate ()
	{
		$priv_key = openssl_pkey_new (array ("digest_alg" => "sha512", "private_key_bits" => self::PKEY_BITS, "private_key_type" => self::PKEY_TYPE));
		
		$pub_key = openssl_pkey_get_details ($priv_key);
		
		if ( $pub_key === false )
			return false;
		
		$this->public_key = $pub_key["key"];
		
		if ( openssl_pkey_export ($priv_key, $this->private_key) === false )
			return false;
		
		return true;
	}
	
	public function getPublicKey ()
	{
		return $this->public_key;
	}
	
	public function getPrivateKey ()
	{
		return $this->private_key;
	}
};

class AsymCrypt
{
	public static function encrypt ($content, AsymCryptKey $key)
	{
		$encrypted_data = null;
		
		if ( $key->getPublicKey () === null )
			return false;
		
		if ( openssl_public_encrypt ($content, $encrypted_data, $key->getPublicKey ()) === false )
			return false;
		
		return bin2hex ($encrypted_data);
	}
	
	public static function decrypt ($content, AsymCryptKey $key)
	{
		$decrypted_data = null;
		
		if ( $key->getPrivateKey () === null )
			return false;
		
		$content = pack ("H*" , $content);
		
		if ( openssl_private_decrypt ($content, $decrypted_data, $key->getPrivateKey ()) === false )
			return false;
		
		return $decrypted_data;
	}
};

$key = new AsymCryptKey ();

echo "generating a key pair ";

if ( $key->generate () === true )
	echo "[ok]\n";
else
	echo "[failed]\n";

$message = "hello world!";

$message_encrypted = AsymCrypt::encrypt ($message, $key);

var_dump ($message_encrypted);

$message_decrypted = AsymCrypt::decrypt ($message_encrypted, $key);

var_dump ($message_decrypted);

?>
