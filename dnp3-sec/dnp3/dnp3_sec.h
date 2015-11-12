//dnp3 security functions

#ifndef DNP3_SECURITY_H
#define DNP3_SECURITY_H

typedef unsigned char uchar;
//errors
#define SEC_RESULT int
#define SEC_SUCCESS 0
#define SEC_ERROR -1
#define SEC_KEYLENGTH_ERROR -2
#define SEC_INDATA_TOOSHORT -3

/*
	hash digest algorithm fips 180-2
	1. Digest algorithm does not require a password
	2. The output of sha1 is 160bit(20B) digest. 
	3. The output of sha256 is 256bit(32B) digest.
*/
#define SHA1_SIZE 20
#define SHA256_SIZE 32

/*
	generated challenge data  fips 186-2
	tips:	1.The length of challenge data required by sha1 is 160bits(20B).
		2.The length of challenge data required by sha256 and aesgmac is 256bits(32B).	
*/
#define CHA_SHA1_SIZE 20
#define CHA_SHA256_SIZE 32
#define CHA_AESGMAC_SIZE 32

SEC_RESULT challenge(const uchar* seed, size_t seedlen, uchar* x, const size_t xlen);

/*
	hmac authentication digest generation algorithm RFC3174
	tips:	1.the output length of sha1		->160bits£¨20B£©£¨serial take out 8B from output,tcpip take out 10B from output).
		2.the output length of sha256	->256bits£¨32B£©£¨serialtake out 8B from output,tcpip take out 16B from output).
		3.the input length of algorithm  ->generate digest use generated challenge data ,the input length of sha1 is 160bits at least,the input length of sha256 is 256bits at least.
		4.key length			->at least 128bits£¨16B£©,it can be longer.
*/
#define MIN_SESSIONKEY_SIZE 16

#define HMAC_SHA1_SERIAL_SIZE 8
#define HMAC_SHA1_TCPIP_SIZE 10
#define HMAC_SHA256_SERIAL_SIZE 8
#define HMAC_SHA256_TCPIP_SIZE 16

SEC_RESULT sha1_hmac(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out);
SEC_RESULT sha256_hmac(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out);
/*
	optional aesmac authentication algorithm NIST SP 800-38D
	tips:	1.the output length is 96bits(12B).
		2.the length of initialization vector IV provided according to protocol requirements is 96bits(12B).
*/
typedef struct _aesgmac_iv{
	uchar sender_lsb;
	uchar sender_msb;
	unsigned short usr;
	unsigned long ksq;
	unsigned long csq;
} aesgmac_iv;

#define HMAC_AESGMAC_SIZE 12

SEC_RESULT aesgmac_hmac(uchar* in,const size_t inlen,aesgmac_iv* iv,uchar* key,const size_t keylen,uchar* out);



/* 
	hmac authentication
	tips:	1.the output length of sha1		->160bits£¨20B£©£¨serial take out 8B from output,tcpip take out 10B from output).
		2.the output length of sha256	->256bits£¨32B£©£¨serialtake out 8B from output,tcpip take out 16B from output).
		3.the input length of algorithm  ->generate digest use generated challenge data ,the input length of sha1 is 160bits at least,the input length of sha256 is 256bits at least.
			4.key length			->at least 128bits£¨16B£©,it can be longer.
*/
SEC_RESULT auth_sha1(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* hash,size_t hashlen);
SEC_RESULT auth_sha256(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* hash, size_t hashlen);
//¿ÉÑ¡
SEC_RESULT auth_aesgmac(uchar* in,const size_t inlen,aesgmac_iv* iv,uchar* key,size_t keylen,uchar* hash,size_t hashlen);

/*
	key wrap algorithm RFC3394
	tips:	1.the input length and key length are multiple of 64bits(8B).
		2.kek length					->kek(updata key) length is 256bits in the aes256 alogrithm,kek(updata key) length is 128bits in the aes128 alogrithm.
		3.the input length£¨session key)	->at least 128bits.
		4.the output length will increase 64bits(8B) after wrap algorithm,in contrast the output length will decrease 64bits(8B) after unwrap algorithm.
*/
#define AES128_KEK_SIZE 16
#define AES256_KEK_SIZE 32
#define KEYWRAP_MIN_KEYSIZE 16
SEC_RESULT aes128_wrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen);
	//optional algorithm
SEC_RESULT aes256_wrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen);


/*
	key unwarp algorithm
*/
SEC_RESULT aes128_unwrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen);
	//optional algorithm
SEC_RESULT aes256_unwrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen);

#endif /* DNP2-SECURITY-H */
