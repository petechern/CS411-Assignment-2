
#include "RSA.h"

#define MOD_SIZE 2048
/**
 * Sets the key to use
 * @param key - the key to use
 * @return - True if the key is valid and False otherwise
 */

bool RSA_433::setKey(const unsigned char* key)
{
	
	/* Open the public key file */
	//const char keyFile[] = key;
	//string keyFile = reinterpret_cast<const char*>(key);
	
	//string keyFile = keyfile;
	FILE* fp = fopen(reinterpret_cast<const char*>(key), "r");
	
	/* Error checks */
	if(!fp)
	{
		perror("fopen");
		return false;		
	}
	
	/* Read the public key */
	pubKey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	
	/* Make sure the file contained a valid key */
	if(!pubKey)
	{
		perror("PEM_read_RSAPublicKey");
		return false;
	}
	


	/******** NOW, LETS READ THE PRIVATE KEY **********/
	
	/* Open the file containing the private key */
	//fp = fopen(keyFile, "r");
	
	/* Error checks */
	//if(!fp)
	//{
	//	perror("fopen");
	//	exit(1);		
	//}
	
	/* Read the private key */
	privKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	
	/* Make sure the file contained a valid key */
	if(!privKey)
	{
		perror("PEM_read_RSAPrivateKey");
		return false;
	}
	
	/* Close the public key file */
	fclose(fp);
	
	return true;
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
 

unsigned char* RSA_433::encrypt(const unsigned char* plaintext)
{
	// int RSA_Encrypt(RSA* rsaKeyPair, unsigned char *in, unsigned char *out, const unsigned int& size ) 
	//printf("EPT: RSA_Encrypt\n");
	//fprintf(stderr, "size: %d\n", size);	
	RSA* rsaKeyPair = pubKey;
	
	/* The number of bytes encrypted */
	int encrypt_len = -1;
	
	/* The buffer containing the error message */
	char errorBuff[130];
	
	int size = strlen(reinterpret_cast<const char*>(plaintext));
	
	/* Encrypt the message using public key */
	unsigned char *in = const_cast<unsigned char*>(plaintext);
	
	unsigned char out[MOD_SIZE];
	
	memset(out, 0, sizeof(out));
	
	if((encrypt_len = RSA_public_encrypt(size, in, out, rsaKeyPair, RSA_PKCS1_OAEP_PADDING)) < 0) 
	{
	    ERR_load_crypto_strings();
	    ERR_error_string(ERR_get_error(), errorBuff);
	    fprintf(stderr, "Error encrypting message: %s\n", errorBuff);
	}
	unsigned char* returnout = out;
	return returnout;
}

/**
 * Decrypts a string of ciphertext
 * @param ciphertext - the ciphertext
 * @return - the plaintext
 */
unsigned char* RSA_433::decrypt(const unsigned char* ciphertext)
{
	return NULL;
}

