#define test
#include "main.c"

#include <assert.h>


void test_transform_pw(const uint8_t *pw, const uint8_t* exp_b64, const uint8_t *exp_out) {
	printf("Testing transform_pw with '%s' ...\n", pw);

	uint8_t b64[32] = {0};
	size_t b64_len = base64_decode(pw, b64);
	assert(b64_len == strlen(exp_b64));
	assert(strcmp(exp_b64, b64) == 0);

	uint8_t out[32] = {0};
	size_t out_len = transform_pw(pw, out);
	assert(out_len == strlen(exp_out));
	assert(strcmp(exp_out, out) == 0);
}


void main() {
	assert(sizeof(FileHeader) == 0x10);
	assert(sizeof(EncHeader) == 0x40);

	test_transform_pw("1", "\xd4\x10\x40", "\xb1\x23\x71");
	test_transform_pw("2", "\xdc\x10\x40", "\xb9\x23\x71");
	test_transform_pw("12", "\xd7\x70\x40", "\xb2\x43\x71");
	test_transform_pw("13", "\xd7\x70\x40", "\xb2\x43\x71");
	test_transform_pw("16", "\xd7\xb0\x40", "\xb2\x83\x71");
	test_transform_pw("123", "\xd7\x6d\xc0", "\xb2\x5e\xf1");
	test_transform_pw("222", "\xdb\x6d\xc0", "\xbe\x5e\xf1");
	test_transform_pw("1234", "\xd7\x6d\xf8", "\xb2\x5e\xc9");
	test_transform_pw("2222", "\xdb\x6d\xb6", "\xbe\x5e\x87");
	test_transform_pw("12345", "\xd7\x6d\xf8\xe4\x10\x40", "\xb2\x5e\xc9\x95\x71\x3a");
	test_transform_pw("123456", "\xd7\x6d\xf8\xe7\xb0\x40", "\xb2\x5e\xc9\x96\xd1\x3a");
	test_transform_pw("123123", "\xd7\x6d\xf5\xdb\x70\x40", "\xb2\x5e\xc4\xaa\x11\x3a");
	test_transform_pw("123[123", "\xd7\x6d\xd7\x6d\xc0", "\xb2\x5e\xe6\x1c\xa1");
	test_transform_pw("123[[123", "\xd7\x6d", "\xb2\x5e");
	test_transform_pw("123[[[123", "\xd7\x6d\xdc\x10\x40", "\xb2\x5e\xed\x61\x21");
	test_transform_pw("123[[[[123", "\xd7\x6d\xdb\x70\x40", "\xb2\x5e\xea\x01\x21");
	test_transform_pw("123[[[[[123", "\xd7\x6d\xd7\x6d\xc0", "\xb2\x5e\xe6\x1c\xa1");
	test_transform_pw("123[[[[[[123", "\xd7\x6d", "\xb2\x5e");
	test_transform_pw("123[", "\xd7\x6d", "\xb2\x5e");
	test_transform_pw("123[4567", "\xd7\x6d\xe3\x9e\xbb", "\xb2\x5e\xd2\xef\xda");
	test_transform_pw("1234[1234", "\xd7\x6d\xf8\xe4\x10\x40", "\xb2\x5e\xc9\x95\x71\x3a");
	test_transform_pw("234]3f32gH?,ewSDg4@23#sa!bL", "\xdb\x7e\xdd\xfd\xf6\x80\x7b\x04\x83\x83", "\xbe\x4d\xec\x8c\x97\xfa\x4e\x70\xe4\xe1");
	test_transform_pw("4738hfkHDse8728Ng5kfd4rJ43f", "\xe3\xbd\xfc\x85\xf9\x07\x0e\xc7\xbc\xef\x6f\x0d\x83\x99\x1f\x77\x8a\xc9\xe3\x77\xc0", "\x86\x8e\xcd\xf4\x98\x7d\x3b\xb3\xdb\x8d\x56\x64\xe9\xf7\x7c\x13\xef\xfa\xd2\x06\xa1");
	test_transform_pw("[", "", "");
	test_transform_pw("", "", "");
}
