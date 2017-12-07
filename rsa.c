
/*
	RSA-lib - Copyright (c) 2017 loreloc - lorenzoloconte@outlook.it

	This software is provided 'as-is', without any express or implied
	warranty. In no event will the authors be held liable for any damages
	arising from the use of this software.

	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:

	1. The origin of this software must not be misrepresented; you must not
	claim that you wrote the original software. If you use this software
	in a product, an acknowledgement in the product documentation would be
	appreciated but is not required.
	2. Altered source versions must be plainly marked as such, and must not be
	misrepresented as being the original software.
	3. This notice may not be removed or altered from any source distribution.
*/

#include "rsa.h"

void rsa_random_prime(mpz_t x, mp_bitcnt_t n)
{
	// number of limbs
	mp_size_t size = (n / 8) / sizeof(mp_limb_t);

	// get a pointer to the x limb array
	mp_limb_t* x_lp = mpz_limbs_write(x, size);

	// generate a random number
	for(mp_size_t i = 0; i < size; ++i)
	{
		// use hardware generated random numbers
		_rdrand64_step(&x_lp[i]);
	}

	// update n limbs
	mpz_limbs_finish(x, size);

	// set the lowest bit
	mpz_setbit(x, 0);

	// set the highest bit
	mpz_setbit(x, n - 1);

	// find the next prime number
	mpz_nextprime(x, x);
}

void rsa_generate_keys(rsa_public_key_t* pbk, rsa_private_key_t* prk, rsa_key_size ks)
{
	// big prime numbers
	mpz_t p, q;
	mpz_init(p);
	mpz_init(q);

	// modulus n, the product of p and q
	mpz_t n;
	mpz_init(n);

	// phi(n), the numbers of numbers less than n and coprime with n
	mpz_t phi;
	mpz_init(phi);
	
	// generate p big prime number
	rsa_random_prime(p, (mp_bitcnt_t)ks / 2);

	// generate q big prime number not equal to p
	do
	{
		rsa_random_prime(q, (mp_bitcnt_t)ks / 2);

	} while(mpz_cmp(p, q) == 0);

	// calculate the modulus n
	mpz_mul(n, p, q);
	mpz_init_set(pbk->n, n);
	mpz_init_set(prk->n, n);

	// calculate phi(n)
	// phi(n) = phi(p*q) = phi(p)*phi(q) = (p-1)*(q-1)
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(phi, p, q);

	// initialize the public exponent
	mpz_init(pbk->e);

	// gcd will hold the greatest commond divisor between e and phi(n)
	mpz_t gcd;
	mpz_init(gcd);

	// find e such that it is coprime with phi(n) and less than phi(n)
	do
	{
		// generate a random prime number of the same size of the prime numbers
		rsa_random_prime(pbk->e, (mp_bitcnt_t)ks / 2);

		// calculate the gcd between e and phi(n)
		mpz_gcd(gcd, pbk->e, phi);

	} while(mpz_cmp_ui(gcd, 1) != 0);

	// initialize the private exponent
	mpz_init(prk->d);

	// find d such that e*d = 1 (mod phi(n))
	mpz_invert(prk->d, pbk->e, phi);

	// clear stuff
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(phi);
	mpz_clear(gcd);
}

void rsa_destroy_public_key(rsa_public_key_t* pbk)
{
	mpz_clear(pbk->n);
	mpz_clear(pbk->e);
}

void rsa_destroy_private_key(rsa_private_key_t* prk)
{
	mpz_clear(prk->n);
	mpz_clear(prk->d);
}

void rsa_encrypt(rsa_public_key_t* pbk, mpz_t c, mpz_t m)
{
	// c = m^e (mod n)
	mpz_powm(c, m, pbk->e, pbk->n);
}

void rsa_decrypt(rsa_private_key_t* prk, mpz_t pt, mpz_t ct)
{
	// m = c^d (mod n)
	mpz_powm(pt, ct, prk->d, prk->n);
}

