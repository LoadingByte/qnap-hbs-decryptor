#define _XOPEN_SOURCE 700
// Support for 64-bit file sizes
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64 

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <openssl/aes.h>


#define HEADER_KEY_LEN 32
#define CONTENT_KEY_LEN 32

const uint8_t *BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const uint8_t *XOR_SECRET = "cde31qaz5tgb9ijn";
const uint8_t *MAGIC = "\x4b\xca\x94\x72\x5e\x83\x1c\x31";


typedef struct {
	uint8_t magic[8];
	uint8_t encrypt;
	uint8_t compressed;
	uint8_t compress_with_header;
	uint8_t _[5]; // unused
} FileHeader;


typedef struct {
	uint8_t magic[8];
	uint8_t content_key[CONTENT_KEY_LEN];
	uint8_t content_iv[16];
	uint8_t file_size[8];
} EncHeader;


void *try_malloc(size_t size) {
	void *ptr = malloc(size);
	if (ptr == NULL) {
		perror("Error while allocating memory");
		exit(EXIT_FAILURE);
	}
	return ptr;
}




// Returns the index of the first occurrence of 'find' or -1 if there is none.
size_t indexof(const uint8_t *in, uint8_t find) {
	uint8_t *ptr = strchr(in, find);
	if (ptr == NULL)
		return -1;
	return ptr - in;
}

// Returns the number of bytes written to 'out'.
size_t base64_decode_group(const uint8_t *in, uint8_t *out) {
	// Note: Using unsigned indices would be correct, but QNAP's code
	// uses signed indices and we have to adhere to their buggy behavior.
	int8_t idx0 = indexof(BASE64, in[0]);
	int8_t idx1 = indexof(BASE64, in[1]);
	if (in[0] == '=' || in[1] == '=' || idx0 == -1 || idx1 == -1)
		return 0;
	out[0] = (idx0 << 2) | (idx1 >> 4);
	int8_t idx2 = indexof(BASE64, in[2]);
	if (in[2] == '=' || idx2 == -1)
		return 1;
	out[1] = (idx1 << 4) | (idx2 >> 2);
	int8_t idx3 = indexof(BASE64, in[3]);
	if (in[3] == '=' || idx3 == -1)
		return 2;
	out[2] = (idx2 << 6) | idx3;
	return 3;
}

size_t base64_decode(const uint8_t *in, uint8_t *out) {
	if (*in == 0)
		return 0;

	// Copy the input string and add four 0 bytes at the end.
	// We do this as we want to stay as close to QNAP's implementation as possible.
	uint8_t *padded_in = calloc(strlen(in) + 4, 1);
	strcpy(padded_in, in);

	uint8_t *in_ptr = padded_in;
	uint8_t *out_ptr = out;
	do {
		out_ptr += base64_decode_group(in_ptr, out_ptr);
		in_ptr += 4;
	} while (*in_ptr != 0);

	free(padded_in);
	return out_ptr - out;
}

void xor_encrypt(uint8_t *arr, size_t arr_len) {
	uint8_t *arr_end = arr + arr_len;
	uint8_t *arr_ptr = arr;
	size_t i = 2;
	while (arr_ptr != arr_end) {
		if (i == 0x10)
			i = 0;
		*arr_ptr++ ^= XOR_SECRET[i++];
	}
}

size_t transform_pw(const uint8_t *in, uint8_t *out) {
	size_t outLen = base64_decode(in, out);
	xor_encrypt(out, outLen);
	return outLen;
}




AES_KEY* prepare_header_key(const char *pw) {
	uint8_t key_str[HEADER_KEY_LEN];
	size_t pw_len = strlen(pw);
	size_t offset = 0;
	for (; offset + pw_len <= HEADER_KEY_LEN; offset += pw_len)
		memcpy(key_str + offset, pw, pw_len);
	if (offset < HEADER_KEY_LEN)
		memcpy(key_str + offset, pw, HEADER_KEY_LEN - offset);

	AES_KEY *key = try_malloc(sizeof(AES_KEY));
	AES_set_decrypt_key(key_str, HEADER_KEY_LEN * 8, key);
	return key;
}

void prepare_header_keys(const char *pw, AES_KEY *header_keys[2]) {
	header_keys[0] = prepare_header_key(pw);

	uint8_t transPw[0x200] = {0};
	uint8_t transpw_len = transform_pw(pw, transPw);
	header_keys[1] = transpw_len == 0 ? NULL : prepare_header_key(transPw);
}




void decrypt_enc_header(const EncHeader *in, EncHeader *out, AES_KEY *header_key) {
	for (size_t offset = 0; offset < sizeof(EncHeader); offset += AES_BLOCK_SIZE)
		AES_ecb_encrypt((uint8_t*) in + offset, (uint8_t*) out + offset, header_key, AES_DECRYPT);
}

uint64_t from_big_endian(uint8_t arr[8]) {
	return arr[7] + 0x100 * (arr[6] + 0x100 * (arr[5] + 0x100 * (arr[4] + 0x100 * (arr[3] + 0x100 * (arr[2] + 0x100 * (arr[1] + 0x100 * (uint64_t) arr[0]))))));
}

bool read_contents(const char *filepath, FILE* file, size_t buf_capacity, bool (*flush_buf)(uint8_t*, size_t), AES_KEY *header_keys[2], FILE *verbose_to) {
	// Read the file header.
	FileHeader file_header;
	fread(&file_header, sizeof(FileHeader), 1, file);
	if (ferror(file)) {
		fprintf(stderr, "[%s] Error while reading from file: %s\n", filepath, strerror(errno));
		return false;
	}
	if (memcmp(file_header.magic, MAGIC, sizeof(MAGIC))) {
		if (verbose_to)
			fprintf(verbose_to, "[%s] Not a HBS encrypted file\n", filepath);
		return false;
	}
	if (!file_header.encrypt) {
		fprintf(stderr, "[%s] Handling of files with HBS header but unset encryption flag is not yet supported\n", filepath);
		return false;
	}
	if (file_header.compressed || file_header.compress_with_header) {
		fprintf(stderr, "[%s] Decryption of compressed files is not yet supported\n", filepath);
		return false;
	}

	// Read and decrypt the encryption header. Try both possible AES keys.
	EncHeader enc_header;
	EncHeader enc_header_tmp;
	fread(&enc_header_tmp, sizeof(EncHeader), 1, file);
	if (ferror(file)) {
		fprintf(stderr, "[%s] Error while reading from file: %s\n", filepath, strerror(errno));
		return false;
	}
	decrypt_enc_header(&enc_header_tmp, &enc_header, header_keys[0]);
	if (memcmp(enc_header.magic, MAGIC, sizeof(MAGIC))) {
		if (header_keys[1] == NULL) {
			fprintf(stderr, "[%s] The regular password does not match and the transformed password comes out empty\n", filepath);
			return false;
		}
		decrypt_enc_header(&enc_header_tmp, &enc_header, header_keys[1]);
		if (memcmp(enc_header.magic, MAGIC, sizeof(MAGIC))) {
			fprintf(stderr, "[%s] The password is incorrect\n", filepath);
			return false;
		}
	}

	// Get the original file's size.
	uint64_t file_len = from_big_endian(enc_header.file_size);

	// If the decrypted file has zero length, flush an empty buffer and return.
	// By handling this case separately, we avoid having to incorporate it into the loop below.
	if (file_len == 0) {
		uint8_t buf[1];
		return flush_buf(buf, 0);
	}

	// Build the content key and get the initialization vector (IV).
	AES_KEY content_key;
	AES_set_decrypt_key(enc_header.content_key, CONTENT_KEY_LEN * 8, &content_key);
	uint8_t *content_iv = enc_header.content_iv;

	// Read blocks from the encrypted file and decrypt them. When the buffer is full,
	// notify the caller and then rewind the buffer.
	bool success = true;
	uint8_t *buf = try_malloc(buf_capacity);
	uint64_t total_len = 0;
	while (total_len < file_len) {
		if (feof(file)) {
			fprintf(stderr, "[%s] File is missing encrypted data at the end: %s\n", filepath, strerror(errno));
			success = false;
			break;
		}
		size_t curr_len = fread(buf, 1, buf_capacity, file);
		if (ferror(file)) {
			fprintf(stderr, "[%s] Error while reading from file: %s\n", filepath, strerror(errno));
			success = false;
			break;
		}
		// When we reach the end of the file, discard the final padding bits.
		if (total_len + curr_len > file_len)
			curr_len = file_len - total_len;
		AES_cbc_encrypt(buf, buf, curr_len, &content_key, content_iv, AES_DECRYPT);
		if (!flush_buf(buf, curr_len)) {
			success = false;
			break;
		}
		total_len += curr_len;
	}
	free(buf);
	return success;
}




bool decrypt_file_in_mem(const char *filepath, uint64_t enc_file_len, AES_KEY *header_keys[2], FILE *verbose_to) {
	FILE* file = fopen(filepath, "rb");
	if (!file) {
		fprintf(stderr, "[%s] Error while opening file for reading: %s\n", filepath, strerror(errno));
		return false;
	}

	bool flush_buf(uint8_t *buf, size_t len) {
		file = freopen(filepath, "wb", file); // Clear the file.
		if (!file) {
			fprintf(stderr, "[%s] Error while reopening file for writing: %s\n", filepath, strerror(errno));
			return false;
		}
		fwrite(buf, 1, len, file);
		if (ferror(file)) {
			fprintf(stderr, "[%s] Error while writing to file: %s\n", filepath, strerror(errno));
			return false;
		}
		return true;
	}

	bool success = read_contents(filepath, file, enc_file_len, flush_buf, header_keys, verbose_to);

	if (file)
		fclose(file);

	return success;
}


bool decrypt_file_in_tmp_file(const char *filepath, AES_KEY *header_keys[2], size_t mem_buf_len, const char *tmppath, FILE *verbose_to) {
	FILE* file = fopen(filepath, "rb");
	if (!file) {
		fprintf(stderr, "[%s] Error while opening file for reading: %s\n", filepath, strerror(errno));
		return false;
	}
	FILE* tmp_file = tmppath ? fopen(tmppath, "wb+") : tmpfile();
	if (!tmp_file) {
		fprintf(stderr, "[%s] Error while opening temporary file for buffering decrypted content: %s\n", filepath, strerror(errno));
		fclose(file); return false;
	}

	bool flush_buf(uint8_t *buf, size_t len) {
		fwrite(buf, 1, len, tmp_file);
		if (ferror(tmp_file)) {
			fprintf(stderr, "[%s] Error while writing decrypted content to temporary file: %s\n", filepath, strerror(errno));
			return false;
		}
		return true;
	}

	bool success = read_contents(filepath, file, mem_buf_len, flush_buf, header_keys, verbose_to);
	if (success) {
		// Try to reserve the buffer before clearing the file, so that we only clear it if we have enough memory.
		uint8_t *buf = try_malloc(mem_buf_len);
		rewind(tmp_file);
		file = freopen(filepath, "wb", file); // Clear the file.
		if (!file) {
			fprintf(stderr, "[%s] Error while reopening file for writing: %s\n", filepath, strerror(errno));
			free(buf); fclose(tmp_file); return false;
		}
		while (!feof(tmp_file)) {
			size_t n_read = fread(buf, 1, mem_buf_len, tmp_file);
			if (ferror(tmp_file)) {
				fprintf(stderr, "[%s] Error while reading decrypted content from temporary file: %s\n", filepath, strerror(errno));
				free(buf); fclose(tmp_file); fclose(file); return false;
			}
			fwrite(buf, 1, n_read, file);
			if (ferror(file)) {
				fprintf(stderr, "[%s] Error while writing decrypted content to file: %s\n", filepath, strerror(errno));
				free(buf); fclose(tmp_file); fclose(file); return false;
			}
		}
		free(buf);
	}

	fclose(tmp_file);
	fclose(file);
	if (tmppath)
		remove(tmppath);

	return success;
}


bool decrypt_file(const char *filepath, uint64_t enc_file_len, AES_KEY *header_keys[2], size_t mem_buf_len, const char *tmppath, FILE *verbose_to) {
	// 'enc_file_len' is larger than the original file's length because of the headers and potential padding,
	// but we may nevertheless use it for roughly determening whether we can decrypt in-memory.
	bool success;
	if (enc_file_len <= mem_buf_len)
		success = decrypt_file_in_mem(filepath, enc_file_len, header_keys, verbose_to);
	else
		success = decrypt_file_in_tmp_file(filepath, header_keys, mem_buf_len, tmppath, verbose_to);

	if (verbose_to && success)
		fprintf(verbose_to, "[%s] Successfully decrypted file\n", filepath);
}


bool decrypt_stdin(AES_KEY *header_keys[2], FILE *verbose_to) {
	bool flush_buf(uint8_t *buf, size_t len) {
		fwrite(buf, 1, len, stdout);
		if (ferror(stdout)) {
			perror("[stdout] Error while writing to stdout");
			return false;
		}
		return true;
	}

	return read_contents("stdin", stdin, 8192, flush_buf, header_keys, verbose_to);
}




bool decrypt_tree(const char *rootpath, AES_KEY *header_keys[2], size_t mem_buf_len, const char *tmppath, FILE *verbose_to) {
	bool all_successful = true;

	int visit_file(const char *filepath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
		if (typeflag == FTW_F) {
			uint64_t enc_file_len = sb->st_size;
			struct timespec file_times[2] = {sb->st_atim, sb->st_mtim};

			if (enc_file_len != 0) {
				all_successful &= decrypt_file(filepath, enc_file_len, header_keys, mem_buf_len, tmppath, verbose_to);

				if (utimensat(AT_FDCWD, filepath, file_times, 0) != 0) {
					fprintf(stderr, "[%s] Error while restoring the access and modification times: %s\n", filepath, strerror(errno));
					all_successful = false;
				}
			}
		}

		// Note: We ignore whether the decryption function was successful for now and continue walking the tree
		// even if an error occurred during decryption.
		return 0;
	}

	if (nftw(rootpath, visit_file, 15, FTW_PHYS /* do not follow symlinks */) != 0) {
		fprintf(stderr, "Error while walking the file tree starting at %s: %s\n", rootpath, strerror(errno));
		return false;
	}

	return all_successful;
}




void print_help(char *arg0) {
	fprintf(stderr,
		"Usage: %s [-p <pw>] [-m <mem>] [-t <tmp>] [-v] [file/dir...]\n"
		"\n"
		"Options:\n"
		"  -p <password>    The password you have set when creating the HBS backup job.\n"
		"                     Omitting this option will lead to an interactive password\n"
		"                     prompt.\n"
		"  -m <memory>      Maximum amount of megabytes in RAM which may be consumed\n"
		"                     for buffering a decrypted file. Decrypting files larger\n"
		"                     than this limit needs a temporary file. Default is 512.\n"
		"  -t <temp file>   Path to a file which may be (over)written with arbitrary\n"
		"                     temporary data. It may become as big as the largest\n"
		"                     decrypted file. Omitting this option will ask the OS for\n"
		"                     a temporary file, which might not fit enough data if your\n"
		"                     decrypted files weigh multiple GB, leading to IO errors.\n"
		"  -v               Enable verbose output. Prints every successfully\n"
		"                     decrypted file and every non-HBS file to stdout, while\n"
		"                     errors are still printed to stderr. Only effective\n"
		"                     when not reading from stdin.\n"
		"\n"
		"When providing files and/or directories as arguments, these files will be\n"
		"decrypted in-place. Caution! That means that their contents will be\n"
		"overwritten, but their file attributes are preserved.\n"
		"\n"
		"If no files or directories are provided, the program expects an encrypted file\n"
		"on stdin and writes the decrypted file to stdout.\n",
		arg0);
}

char *hidden_prompt(size_t buf_len) {
	static struct termios oldt, newt;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ECHO);          
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	char *str = malloc(buf_len);
	fgets(str, buf_len, stdin);
	str[strcspn(str, "\n\r")] = 0;

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return str;
}

char *_handler_tmppath; // Must be global because main()'s local variables will be gone when exit_handler() is called.
void exit_handler() { remove(_handler_tmppath); }
void signal_handler() { /* remove() is not signal-safe */ unlink(_handler_tmppath); _Exit(EXIT_FAILURE); };

#ifndef test
int main(int argc, char *argv[]) {
	char *pw = NULL;
	size_t mem_buf_len = 512 /* MB */ * 0x100000;
	char *tmppath = NULL;
	bool verbose = false;

	opterr = 0; // Disallow getopt() to print its own error messages.
	int opt;
	while ((opt = getopt(argc, argv, "p:m:t:v")) != -1) {
		switch (opt) {
			case 'p': pw = optarg; break;
			case 'm':
				long l = strtol(optarg, NULL, 10);
				if (l <= 0) {
					print_help(argv[0]);
					return EXIT_FAILURE;
				} else
					mem_buf_len = (size_t) l * 0x100000;
				break;
			case 't': tmppath = optarg; break;
			case 'v': verbose = true; break;
			case '?':
				print_help(argv[0]);
				return EXIT_FAILURE;
		}}

	// Prompt the user for the password if he did not specify it as an option.
	if (pw == NULL) {
		fprintf(stdout, "Password: ");
		pw = hidden_prompt(1024);
		fprintf(stdout, "\n");
	}

	// Register handlers that delete the user-located temporary file when the program exits.
	if (tmppath) {
		_handler_tmppath = tmppath;
		atexit(exit_handler);
		signal(SIGTERM, signal_handler);
		signal(SIGINT, signal_handler);
	}

	AES_KEY *header_keys[2];
	prepare_header_keys(pw, header_keys);

	bool success;
	if (optind == argc)
		success = decrypt_stdin(header_keys, /* verbose_to = */ stderr);
	else
		success = true;
		for (int i = optind; i < argc; i++)
			success &= decrypt_tree(/* filepath = */ argv[i], header_keys, mem_buf_len, tmppath, /* verbose_to = */ verbose ? stdout : NULL);

	return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
#endif
