/**
 * This file illustrates how encrypt and decrypt using 
 * RSA in the openssl library.
 * For more information see the following link:
 * http://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/
 */


#include <iostream>
#include "RSA.h"

using namespace std;

int main() {
	int whatever = 2;
	
	RSA_433 *rsatest = new RSA_433();
	const unsigned char keyfile[] = "pubkey.pem";
	
	rsatest->setKey(keyfile);
	cout << rsatest->encrypt((const unsigned char*)"hello");
	
	return 0;
}



