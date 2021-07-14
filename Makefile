main:
	gcc -O3 -lcrypto -o qnap-hbs-decryptor main.c

test:
	gcc -lcrypto -o test test.c
	./test
	rm test
