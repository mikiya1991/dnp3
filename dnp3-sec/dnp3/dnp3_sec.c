#include <string.h>
#include "dnp3_sec.h"

SEC_RESULT sha1(uchar* in,const size_t inlen,uchar* out){
	if(!in && out) return SEC_ERROR;
	memcpy(out,in,SHA1_SIZE);
	return SEC_SUCCESS;
}
SEC_RESULT sha256(uchar* in,const size_t inlen,uchar* out){
	if(!in && out) return SEC_ERROR;
	memcpy(out,in,SHA256_SIZE);
	return SEC_SUCCESS;
}

SEC_RESULT aes(uchar* in,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	memcpy(out,in,8);
	return SEC_SUCCESS;
}
SEC_RESULT aes_decrypt(uchar* in,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	memcpy(out,in,8);
	return SEC_SUCCESS;
}

SEC_RESULT challenge_sha1(const uchar* seed, size_t seedlen, uchar* out){
	if(!seed && out) return SEC_ERROR;
	if(seedlen>=CHA_SHA1_SIZE){
		memcpy(out,seed,CHA_SHA1_SIZE);	
	}
	else{
		int restlen = CHA_SHA1_SIZE;
		uchar* po = out;
		while(restlen>0){
			if(restlen>seedlen) memcpy(po,seed,seedlen);
			else memcpy(po,seed,restlen);
			restlen-=seedlen;
			po+=seedlen;
		}
	}
	return SEC_SUCCESS;
}

SEC_RESULT challenge_sha256(const uchar* seed, size_t seedlen, uchar* out){
	if(!seed && out) return SEC_ERROR;
	if(seedlen>=CHA_SHA256_SIZE){
		memcpy(out,seed,CHA_SHA256_SIZE);	
	}
	else{
		int restlen = CHA_SHA256_SIZE;
		uchar* po = out;
		while(restlen>0){
			if(restlen>seedlen) memcpy(po,seed,seedlen);
			else memcpy(po,seed,restlen);
			restlen-=seedlen;
			po+=seedlen;
		}
	}
	return SEC_SUCCESS;
}
SEC_RESULT challenge_aesgmac(const uchar* seed, size_t seedlen, uchar* out){
	if(!seed && out) return SEC_ERROR;
	if(seedlen>=CHA_SHA256_SIZE){
		memcpy(out,seed,CHA_SHA256_SIZE);	
	}
	else{
		int restlen = CHA_SHA256_SIZE;
		uchar* po = out;
		while(restlen>0){
			if(restlen>seedlen) memcpy(po,seed,seedlen);
			else memcpy(po,seed,restlen);
			restlen-=seedlen;
			po+=seedlen;
		}
	}
	return SEC_SUCCESS;
}


SEC_RESULT hmac_sha1_serial(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	uchar mac[SHA1_SIZE];
	sha1(in,inlen,mac);
	memcpy(out,mac,HMAC_SHA1_SERIAL_SIZE);
	return SEC_SUCCESS;
}
SEC_RESULT hmac_sha1_tcpip(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	uchar mac[SHA1_SIZE];
	sha1(in,inlen,mac);
	memcpy(out,mac,HMAC_SHA1_TCPIP_SIZE);
	return SEC_SUCCESS;
}
SEC_RESULT hmac_sha256_serial(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	uchar mac[SHA256_SIZE];
	sha256(in,inlen,mac);
	memcpy(out,mac,HMAC_SHA256_SERIAL_SIZE);
	return SEC_SUCCESS;
}
SEC_RESULT hmac_sha256_tcpip(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	uchar mac[SHA256_SIZE];
	sha256(in,inlen,mac);
	memcpy(out,mac,HMAC_SHA256_TCPIP_SIZE);
	return SEC_SUCCESS;
}



SEC_RESULT hmac_aesgmac(uchar* in,const size_t inlen,aesgmac_iv* iv,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	memcpy(in,out,HMAC_AESGMAC_SIZE);
	return SEC_SUCCESS;
}



SEC_RESULT auth_sha1_serial(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* inhash){
	if(! in && inhash) return SEC_ERROR;
	uchar mhash[HMAC_SHA1_SERIAL_SIZE];
	hmac_sha1_serial(in,inlen,key,keylen,mhash);
	int res = memcmp(mhash,inhash,HMAC_SHA1_SERIAL_SIZE);
	if(!res) return SEC_SUCCESS;
	return SEC_ERROR;
}
SEC_RESULT auth_sha1_tcpip(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* inhash){
	if(! in && inhash) return SEC_ERROR;
	uchar mhash[HMAC_SHA1_TCPIP_SIZE];
	hmac_sha1_tcpip(in,inlen,key,keylen,mhash);
	int res = memcmp(mhash,inhash,HMAC_SHA1_TCPIP_SIZE);
	if(!res) return SEC_SUCCESS;
	return SEC_ERROR;
}
SEC_RESULT auth_sha256_serial(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* inhash){
	if(! in && inhash) return SEC_ERROR;
	uchar mhash[HMAC_SHA256_SERIAL_SIZE];
	hmac_sha256_serial(in,inlen,key,keylen,mhash);
	int res = memcmp(mhash,inhash,HMAC_SHA256_SERIAL_SIZE);
	if(!res) return SEC_SUCCESS;
	return SEC_ERROR;
}
SEC_RESULT auth_sha256_tcpip(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* inhash){
	if(! in && inhash) return SEC_ERROR;
	uchar mhash[HMAC_SHA256_TCPIP_SIZE];
	hmac_sha256_tcpip(in,inlen,key,keylen,mhash);
	int res = memcmp(mhash,inhash,HMAC_SHA256_TCPIP_SIZE);
	if(!res) return SEC_SUCCESS;
	return SEC_ERROR;
}

SEC_RESULT auth_aesgmac(uchar* in,const size_t inlen,aesgmac_iv* iv,uchar* key,size_t keylen,uchar* inhash){
	if(! in && inhash) return SEC_ERROR;
	uchar mac[HMAC_AESGMAC_SIZE];
	hmac_aesgmac(in,inlen,iv,key,keylen,mac);
	int res = memcmp(mac,inhash,HMAC_AESGMAC_SIZE);
	if(!res) return SEC_SUCCESS;
	else return SEC_ERROR;
}



SEC_RESULT aes128_wrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
	if(! in && out) return SEC_ERROR;
	int r = inlen % 8;
	int q = inlen/8;
	int olen = inlen;
	if(r>0) olen = (q+1)*8;
	else olen = q*8;
	uchar* po = out;
	memcpy(po,in,inlen);
	po+=inlen;
	memset(po,0,8+olen-inlen);
	*outlen = olen+8;
	return SEC_SUCCESS;
}

SEC_RESULT aes256_wrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
	if(! in && out) return SEC_ERROR;
	int r = inlen % 8;
	int q = inlen/8;
	int olen = inlen;
	if(r>0) olen = (q+1)*8;
	else olen = q*8;
	uchar* po = out;
	memcpy(po,in,inlen);
	po+=inlen;
	memset(po,0,8+olen-inlen);
	*outlen = olen+8;
	return SEC_SUCCESS;
}


SEC_RESULT aes128_unwrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
	if(! in && out) return SEC_ERROR;
	memcpy(out,in,inlen-8);
	*outlen = inlen-8;
	return SEC_SUCCESS;
}


SEC_RESULT aes256_unwrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
	if(! in && out) return SEC_ERROR;
	memcpy(out,in,inlen-8);
	*outlen = inlen-8;
	return SEC_SUCCESS;
}










