#ifndef _AES_VECTORTABLE_
#define _AES_VECTORTABLE_

#include <stdint.h>


typedef struct  {
  CHAR8* msg;
  CHAR8* answer;
  CHAR8 *key;
  CHAR8* iv;
  UINTN  len;
}SBCAESTestVectorMsg_t;


SBCAESTestVectorMsg_t gt_aescbc_vector[] = {
	{
		.key = "8000000000000000000000000000000000000000000000000000000000000000",
		.iv = "00000000000000000000000000000000",
		.msg = "00000000000000000000000000000000",
		.answer = "e35a6dcb19b201a01ebcfa8aa22b5759",
		.len = 0
		//c4c51bb178814440f25994c287255626
	},
	{
		.key = "c000000000000000000000000000000000000000000000000000000000000000",
		.iv = "00000000000000000000000000000000",
		.msg = "00000000000000000000000000000000",
		.answer = "b29169cdcf2d83e838125a12ee6aa400",
		.len = 0
	},
	{
		.key = "ffffffff80000000000000000000000000000000000000000000000000000000",
		.iv = "00000000000000000000000000000000",
		.msg = "00000000000000000000000000000000",
		.answer = "33ac9eccc4cc75e2711618f80b1548e8",
		.len  = 0
	},
	{
		.key = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000",
		.iv = "00000000000000000000000000000000",
		.msg = "00000000000000000000000000000000",
		.answer = "52fc3e620492ea99641ea168da5b6d52",
		.len = 0
	},
	{
		.key = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000",
		.iv = "00000000000000000000000000000000",
		.msg = "00000000000000000000000000000000",
		.answer = "3a0a0e75a8da36735aee6684d965a778",
		.len = 0
	}

};

struct aes_gcm_vectors_st {
	const uint8_t *key;
	const uint8_t *auth;
	int auth_size;
	const uint8_t *plaintext;
	int plaintext_size;
	const uint8_t *iv;
	const uint8_t *ciphertext;
	const uint8_t *tag;
};

struct aes_gcm_vectors_st aes_gcm_vectors[] = {
	{
	 .key = (uint8_t *)
	 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .auth = NULL,
	 .auth_size = 0,
	 .plaintext = (uint8_t *)
	 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .plaintext_size = 16,
	 .ciphertext = (uint8_t *)
	 "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
	 .iv = (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .tag = (uint8_t *)
	 "\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf"
	},
	{
	 .key = (uint8_t *)
	 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
	 .auth = NULL,
	 .auth_size = 0,
	 .plaintext = (uint8_t *)
	 "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55",
	 .plaintext_size = 64,
	 .ciphertext = (uint8_t *)
	 "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91\x47\x3f\x59\x85",
	 .iv = (uint8_t *)"\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88",
	 .tag = (uint8_t *)"\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4"
	},
	{
	 .key = (uint8_t *)
	 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
	 .auth = (uint8_t *)
	 "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2",
	 .auth_size = 20,
	 .plaintext = (uint8_t *)
	 "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
	 .plaintext_size = 60,
	 .ciphertext = (uint8_t *)
	 "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91",
	 .iv = (uint8_t *)"\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88",
	 .tag = (uint8_t *)
	 "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47"
	}
};
#endif
