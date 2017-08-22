#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

unsigned char buffer[2000];

int main(int argc,char **argv)
{

    // ---------------------------------- MD5 example --------------------------------------------

    gcry_md_hd_t handle;
    FILE *fd;

    size_t len;
    int a;

    if(argc<2)
    {
    fprintf(stderr,"usage: %s <file>\n",*argv);
    return 1;
    }
    if( (fd=fopen(*(argv+1),"r")) ==NULL)
    {
    perror("Couldn't open file!\n");
    return 1;
    }

    //gcry_control( GCRYCTL_DISABLE_SECMEM_WARN );
    gcry_control( GCRYCTL_INIT_SECMEM, 16384, 0 );

    gcry_error_t err = 0;

    err=gcry_md_open(&handle, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);

    if( (len=fread(buffer,sizeof(unsigned char),2000,fd)) ==0)
    {
        if(ferror(fd))
        {
            perror("Couldn't read file!\n");
            return 1;
        }
    }
    printf("len: %d\n", (int)len);
    gcry_md_write(handle,buffer,len); /*<-- this should create the checksum*/
    gcry_md_final(handle);

    printf("%s\n",buffer);

    char tmp[65] = {0};

    snprintf(tmp, 65, "%s", gcry_md_read(handle, GCRY_MD_SHA512));

    int i = 0;

    // Print out the hash!
    for (i = 0; i < 64; i++)
        printf("%02x", (unsigned char)tmp[i]);

    gcry_md_close(handle);


    // ---------------------------------- PBKFD example --------------------------------------------

    #define AES256_KEY_SIZE     32
    #define AES256_BLOCK_SIZE   16
    #define HMAC_KEY_SIZE       64

    #define KDF_ITERATIONS      1000
    #define KDF_SALT_SIZE       32
    #define KDF_KEY_SIZE        AES256_KEY_SIZE


     char kdf_salt[KDF_SALT_SIZE] = {0};
     char kdf_key[KDF_KEY_SIZE];

    // Generate 128 byte salt in preparation for key derivation
    gcry_create_nonce(kdf_salt, KDF_SALT_SIZE);


    // Key derivation: PBKDF2 using SHA512 w/ 128 byte salt over 10 iterations into a 64 byte key
    err = gcry_kdf_derive("hello",
                        strlen("hello"),
                        GCRY_KDF_PBKDF2,
                        GCRY_MD_SHA512,
                        kdf_salt,
                        KDF_SALT_SIZE,
                        KDF_ITERATIONS,
                        KDF_KEY_SIZE,
                        kdf_key);
    if (err) {
        fprintf(stderr, "kdf_derive: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
        return 1;
    }


    printf("\nSALT\n");

    for (i = 0; i < 32; i++)
        printf("%02x", (unsigned char)kdf_salt[i]);



    printf("\nPBKDF2\n");

    for (i = 0; i < 32; i++)
        printf("%02x", (unsigned char)kdf_key[i]);


    return 0;
}


