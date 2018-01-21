#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

int my_better_rand_bytes(unsigned char *buf, int num_bytes);

int main (int argc, char *argv[])
{

    // Normal house keeping
    char *pub_key_file = "server_pubkey.pub";
    FILE *fp;
    int num_bits = 2048; 

    // This is a recommend public exponent everyone uses. 65537.
    unsigned long exponent = RSA_F4; 
    
    // Initializing the same way that victim does                           
    RAND_METHOD my_better_random_method;

    memset(&my_better_random_method, 0x00, sizeof(RAND_METHOD));

    my_better_random_method.pseudorand = my_better_rand_bytes;
    my_better_random_method.bytes = my_better_rand_bytes;
   
    RAND_set_rand_method(&my_better_random_method);

    // Read in public key
    RSA *my_rsa = malloc(sizeof(RSA));

    if (!(fp = fopen(pub_key_file, "r"))){
        fprintf(stderr, "Could not open public key file %s\n", pub_key_file);
        exit(1);
    }
    if (!PEM_read_RSAPublicKey(fp, &my_rsa, NULL, NULL))
    {
        fprintf(stderr, "Could not write public key file %s\n", pub_key_file);
        exit(1);
    }
    fclose(fp);

    for (int seed = 7812; seed >= 0; seed--) {
        // Seed my random function with current seed
        srand(seed);
   
        // Create our key
        RSA *rsa = RSA_generate_key(num_bits,exponent,NULL,NULL);

        if (!BN_cmp(my_rsa->n, rsa->n)) {
            // Write private key to stdout
            PEM_write_RSAPrivateKey(stdout,rsa,NULL,NULL,0,NULL,NULL);

            free(my_rsa);
            exit(0); // Hacking success!
	   }
    }

    exit(1); // Hacking failure :(

}

// Victim's code to generate random numbers from seed
int my_better_rand_bytes(unsigned char *buf, int num_bytes)
{

    for (int i = 0; i < num_bytes; i+=4)
    {
            int rand_int = rand();
#define min(a,b) (((a)<(b))?(a):(b))
            memcpy(buf + i, &rand_int, min(num_bytes - i,4));
    }
         
    return 1; // 1 means good!
}
