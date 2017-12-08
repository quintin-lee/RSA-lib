
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rsa.h"

int main(int argc, char* argv[])
{
	rsa_public_key_t public_key;
	rsa_private_key_t private_key;

	clock_t start, end;

	start = clock();

	// generate the public and the private keys
	rsa_generate_keys(&public_key, &private_key, RSA_KEY_512);

	end = clock();

	printf("Keys generation time: %f s\n\n", (float)(end - start) / CLOCKS_PER_SEC);

	uint8_t plaintext[1054] =
		"The quick, brown fox jumps over a lazy dog. DJs flock by when MTV ax quiz prog. Junk MTV quiz graced by fox whelps. Bawds jog, flick quartz, vex nymphs."
		"Waltz, bad nymph, for quick jigs vex! Fox nymphs grab quick-jived waltz. Brick quiz whangs jumpy veldt fox. Bright vixens jump; dozy fowl quack."
		"Quick wafting zephyrs vex bold Jim. Quick zephyrs blow, vexing daft Jim. Sex-charged fop blew my junk TV quiz. How quickly daft jumping zebras vex."
		"Two driven jocks help fax my big quiz. Quick, Baz, get my woven flax jodhpurs! 'Now fax quiz Jack!' my brave ghost pled. Five quacking zephyrs jolt my wax bed."
		"Flummoxed by job, kvetching W. zaps Iraq. Cozy sphinx waves quart jug of bad milk. A very bad quack might jinx zippy fowls. Few quips galvanized the mock jury box."
		"Quick brown dogs jump over the lazy fox. The jay, pig, fox, zebra, and my wolves quack! Blowzy red vixens fight for a quick jump."
		"Joaquin Phoenix was gazed by MTV for luck. A wizard's job is to vex chumps quickly in fog. Watch 'Jeopardy!', Alex Trebek's fun TV quiz game."
		"............";

	printf("Message to encrypt : %s\n\n", (char*)plaintext);

	// get the chiper text size for encrypting the plaintext
	size_t chipertext_size = rsa_chipertext_size(&public_key, sizeof(plaintext));

	uint8_t* chipertext = (uint8_t*)malloc(chipertext_size);

	if(!chipertext)
		return 1;

	// clear the chipertext
	memset(chipertext, '\0', chipertext_size);

	// encrypt the chipertext
	rsa_encrypt(&public_key, chipertext, plaintext, sizeof(plaintext));

	// clear the plaintext
	memset(plaintext, '\0', sizeof(plaintext));

	// decrypt the chipertext
	rsa_decrypt(&private_key, plaintext, chipertext, chipertext_size);

	printf("Message decrypted : %s\n", (char*)plaintext);

	free(chipertext);

	// destroy the public and private keys
	rsa_destroy_public_key(&public_key);
	rsa_destroy_private_key(&private_key);

	return 0;
}

