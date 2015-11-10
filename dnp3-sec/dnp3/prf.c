#include "crypto.h"

SEC_RESULT challenge(const uchar* seed, size_t seedlen, uchar* x, const size_t xlen){
	int r,q;
	r = xlen%40;
	q = xlen/40;
	if(r>0) q++;
	uchar* changedata = (uchar*) malloc(q*40);
	if(!changedata) return SEC_ERROR;
	
	int ret_chan = fips186_2_prf(seed,seedlen,changedata,q*40);
	if(!ret_chan){
		memcpy(changedata,x,xlen);
		free(changedata);
		return SEC_SUCCESS;
	}
	else{
		free(changedata);
		return SEC_ERROR;
	}
}
