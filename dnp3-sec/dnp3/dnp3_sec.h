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
	hash 摘要算法 fips 180-2
	1. 摘要算法本身不需要密码
	2. sha1输出160bits(20B)摘要
	3. sha256输出256bits(32B)摘要
*/
#define SHA1_SIZE 20
#define SHA256_SIZE 32

/*
	challenge data 挑战值的生成 fips 186-2
	tips:	1.sha1要求的挑战长度为160bits（20B）
			2.sha256和aesgmac要求的挑战为256bits（32B）	
*/
#define CHA_SHA1_SIZE 20
#define CHA_SHA256_SIZE 32
#define CHA_AESGMAC_SIZE 32

SEC_RESULT challenge(const uchar* seed, size_t seedlen, uchar* x, const size_t xlen);

/*
	hmac认证摘要生成算法 RFC3174
	tips:	1.输出长度sha1		->160bits（20B）（serial截取8B，tcpip截取10B）。
			2.输出长度sha256	->256bits（32B）（serial截取8B，tcpip截取16B）。
			3.输入长度			->对生成的挑战做摘要，sha1输入至少为160bits，sha256至少256bits。
			4.key长度			->至少128bits（16B）,可大于此长度。
*/

#define HMAC_SHA1_SERIAL_SIZE 8
#define HMAC_SHA1_TCPIP_SIZE 10
#define HMAC_SHA256_SERIAL_SIZE 8
#define HMAC_SHA256_TCPIP_SIZE 16

SEC_RESULT sha1_hmac(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out);
SEC_RESULT sha256_hmac(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out);
/*
	可选aesgmac认证算法 NIST SP 800-38D
	tips:	1.输出长度96bits(12B)
			2.初始化向量IV 96bits（12B），根据协议要求提供。
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
	hmac 认证
	tips： 要求同上面相同
*/
SEC_RESULT auth_sha1(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* hash,size_t hashlen);
SEC_RESULT auth_sha256(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* hash, size_t hashlen);
//可选
SEC_RESULT auth_aesgmac(uchar* in,const size_t inlen,aesgmac_iv* iv,uchar* key,size_t keylen,uchar* hash,size_t hashlen);

/*
	key warp algorithm RFC3394
	tips:	1.输入和key的长度皆为64bits(8B)倍数
			2.kek长度					->aes256的kek（update key）为256bits,aes128为128bits
			3.输入长度（session key)	->至少128bits
			4.wrap之后会多出64bits（8B），unwrap减少8B
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
