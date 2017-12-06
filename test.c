
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "rsa.h"

int main(int argc, char* argv[])
{
	rsa_public_key_t public_key;
	rsa_private_key_t private_key;

	clock_t start, end;

	start = clock();

	// generate the public and the private keys
	rsa_generate_keys(&public_key, &private_key, RSA_KEY_2048);

	end = clock();

	printf("Keys generation time: %f s\n\n", (float)(end - start) / CLOCKS_PER_SEC);

	char message[13] = "Hello World!";
	printf("Message to encrypt : %s\n\n", message);

	mpz_t msg;
	mpz_init(msg);

	// encryption stage
	mpz_import(msg, 13, 1, 1, 0, 0, message);
	rsa_encrypt(&public_key, msg, msg);
	gmp_printf("Encrypted message : %Zx\n", msg);
	printf("\n");

	// decryption stage
	char plain_text[13] = "";
	rsa_decrypt(&private_key, msg, msg);
	mpz_export(plain_text, NULL, 1, 1, 0, 0, msg);
	printf("Decrypted message : %s\n", plain_text);

	mpz_clear(msg);

	// destroy the public and private keys
	rsa_destroy_public_key(&public_key);
	rsa_destroy_private_key(&private_key);

	return 0;
}

