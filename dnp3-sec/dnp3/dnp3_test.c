#include <stdio.h>
#include <string.h>
#include "dnp3_sec.h"

enum HMAC_FUN {SHA1,SHA256,AESGMAC};
void pt(uchar* s,size_t len){
	uchar* p = s;
	int i;
	for(i=0;i<len;i++) printf("%2x",*p++);
	printf("\n");
}
int main(){
	uchar sessionkey[16];
	//set session key
	const int skeylen = 16;
	memcpy(sessionkey,"iamtestsessionkeyfordnp3security",skeylen);
	printf("sessionkey: ");
	pt(sessionkey,skeylen);

	//choose protocol
	int protocol=0;
	switch(protocol){
	case SHA1:
		{
			//generate challenge
			uchar chan[CHA_SHA1_SIZE];
			challenge_sha1(sessionkey,skeylen,chan);
			printf("challenge content: ");
			pt(chan,CHA_SHA1_SIZE);
			//generate hash
			uchar hash[HMAC_SHA1_SERIAL_SIZE];
			hmac_sha1_serial(chan,CHA_SHA1_SIZE,sessionkey,skeylen,hash);
			printf("challenge hash: ");
			pt(hash,HMAC_SHA1_SERIAL_SIZE);
			//authenaticate hash
			int res = auth_sha1_serial(chan,skeylen,sessionkey,skeylen,hash);
			printf("auth result: %d\n",res);
		}
		break;
	case SHA256:
		break;
	case AESGMAC:
		break;
	}
	return 0;		
}
