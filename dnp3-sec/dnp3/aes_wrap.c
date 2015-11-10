#include "crypto.h"
#include "aes_wrap.h"

#include "includes.h"
#include "common.h"

SEC_RESULT aes128_wrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
	if(!in&&out) return SEC_ERROR;
	if(KEKlen != 16) return SEC_KEYLENGTH_ERROR;
	// len check and alloc buffer
	int r,q;
	r = inlen % 8;
	q = inlen / 8;
	uchar* buf;
	bool bufflag = 0;
	if(!r) buf = in;
	else{
		bufflag = 1;
		q++;
		buf = malloc(q*8);
		memset(buf,0,q*8);
		memcpy(buf,in,inlen);
	}
	//algorithim
	int ret = aeswrap(KEK,q,buf,out);
	if(bufflag) free(buf);
	if(!ret){
		*outlen = inlen+8;
		return SEC_SUCCESS;
	}
	else{
		return SEC_ERROR;
	}
}
SEC_RESULT aes128_unwrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
	if(!in&&out) return SEC_ERROR;
	if(KEKlen != 16) return SEC_KEYLENGTH_ERROR; 
	// in data length check
	int r,q;
	r = inlen % 8;
	q = inlen / 8;
	if(r) return SEC_ERROR;
	int ret = aes_unwrap(KEK,q,in,out);
	if(!ret){
		*outlen = inlen-8;
		return SEC_SUCCESS;
	}
	else{
		return SEC_ERROR;
	}
}

SEC_RESULT aes256_wrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
}

SEC_RESULT aes256_unwrap(uchar* in,const size_t inlen,uchar* KEK,const size_t KEKlen,uchar* out,size_t *const outlen){
}







