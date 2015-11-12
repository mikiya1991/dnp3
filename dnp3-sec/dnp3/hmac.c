#include "sha1.h"
#include "sha256.h"
SEC_RESULT sha1_hmac(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	//check keylen and datalen
	if(keylen<MIN_SESSIONKEY_SIZE) return SEC_KEYLENGTH_ERROR;

	int ret = hmac_sha1(key,keylen,in,inlen,out);
	if(ret) return SEC_ERROR;
	return SEC_SUCCESS;
}
SEC_RESULT sha256_hmac(uchar* in,const size_t inlen,uchar* key,const size_t keylen,uchar* out){
	if(!in && out) return SEC_ERROR;
	//check keylen and datalen
	if(keylen<MIN_SESSIONKEY_SIZE) return SEC_KEYLENGTH_ERROR;

	int ret = hmac_sha256(key,keylen,in,inlen,out);
	if(ret) return SEC_ERROR;
	return SEC_SUCCESS;
}
SEC_RESULT auth_sha1(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* hash,size_t hashlen){
	uchar* datahash = (uchar*)malloc(SHA1_SIZE);
	if(!datahash) return SEC_ERROR;
	int ret = sha1_hmac(in,inlen,key,keylen,datahash);
	if(ret){
		free(datahash);
		return SEC_ERROR;
	}
	int ret_cmp = memcmp(datahash,hash,hashlen);
	free(datahash);
	if(ret_cmp) return SEC_ERROR;
	return SEC_SUCCESS;
	
}
SEC_RESULT auth_sha256(uchar* in,const size_t inlen,uchar* key,size_t keylen,uchar* hash, size_t hashlen){
	uchar* datahash = (uchar*)malloc(SHA256_SIZE);
	if(!datahash) return SEC_ERROR;
	int ret = sha256_hmac(in,inlen,key,keylen,datahash);
	if(ret){
		free(datahash);
		return SEC_ERROR;
	}
	int ret_cmp = memcmp(datahash,hash,hashlen);
	free(datahash);
	if(ret_cmp) return SEC_ERROR;
	return SEC_SUCCESS;
}

SEC_RESULT aesgmac_hmac(uchar* in,const size_t inlen,aesgmac_iv* iv,uchar* key,const size_t keylen,uchar* out){

}

SEC_RESULT auth_aesgmac(uchar* in,const size_t inlen,aesgmac_iv* iv,uchar* key,size_t keylen,uchar* hash,size_t hashlen){


}

