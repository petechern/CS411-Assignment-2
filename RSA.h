
#ifndef RSA_H
#define RSA_H
#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <string.h>
#include "CipherInterface.h"

using namespace std;

/** 
 * Implements an RSA cipher
 */
class RSA_433: public CipherInterface
{
	/* The public members */
	public:
		
		/**
		 * The default constructor
	 	 */
		RSA_433(){
			pubKey = new RSA();
			privKey = new RSA();
		}
			
		/**
		 * Sets the key to use
		 * @param key - the key to use
		 * @return - True if the key is valid and False otherwise
		 */
		virtual bool setKey(const unsigned char* key);

		/**	
		 * Encrypts a plaintext string
		 * @param plaintext - the plaintext string
		 * @return - the encrypted ciphertext string
		 */
		virtual unsigned char* encrypt(const unsigned char* plaintext);

		/**
		 * Decrypts a string of ciphertext
		 * @param ciphertext - the ciphertext
		 * @return - the plaintext
		 */
		virtual unsigned char* decrypt(const unsigned char* ciphertext);
	
		
	/* The protected members */
	//protected:
	
	protected:
		RSA* pubKey;
		RSA* privKey;

};


#endif
