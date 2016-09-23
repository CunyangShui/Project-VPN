#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>  

#define EVP_AES_CBC EVP_aes_128_cbc()

unsigned char *decrypt_text(unsigned char *iv, unsigned char *key, unsigned char *ciphertext, int *ciphertext_len, unsigned char* plaintext, int* output_len) {
    
    EVP_CIPHER_CTX de;
    EVP_CIPHER_CTX_init(&de);
    const EVP_CIPHER *cipher_type;
    
    *output_len = 0;
    int update_len = 0;
    cipher_type = EVP_AES_CBC;
    
    EVP_DecryptInit_ex(&de, cipher_type, NULL, key, iv);
    
    if(!EVP_DecryptInit_ex(&de, NULL, NULL, NULL, NULL)){
        printf("ERROR in EVP_DecryptInit_ex \n");
        return NULL;
    }
    
    int plaintext_len = 0;
    if(!EVP_DecryptUpdate(&de, plaintext, &update_len, ciphertext, *ciphertext_len))
    {
        printf("ERROR in EVP_DecryptUpdate\n");
        return NULL;
    }
    
    if(!EVP_DecryptFinal_ex(&de, plaintext + update_len, output_len))
    {
        printf("ERROR in EVP_DecryptFinal_ex\n");
        return NULL;
    }
    *output_len += update_len;
    *(plaintext+*output_len) = '\0';
    
    printf("decryption complete (%d->%d)\n", *ciphertext_len, *output_len);
    
    EVP_CIPHER_CTX_cleanup(&de);
    
    return plaintext;
}

unsigned char *encrypt_text(unsigned char *iv, unsigned char *key, unsigned char *plaintext, int input_len, unsigned char *ciphertext, int *ciphertext_len ) {
    
    EVP_CIPHER_CTX en;
    EVP_CIPHER_CTX_init(&en);
    const EVP_CIPHER *cipher_type;
    //int input_len = 0;
    
    cipher_type = EVP_AES_CBC;
    EVP_EncryptInit_ex(&en, cipher_type, NULL, key, iv);
    //input_len = l;
    
    if(!EVP_EncryptInit_ex(&en, NULL, NULL, NULL, NULL)){
        printf("ERROR in EVP_EncryptInit_ex \n");
        return NULL;
    }
    
    int bytes_written = 0;
    //encrypt
    if(!EVP_EncryptUpdate(&en, ciphertext, &bytes_written, (unsigned char *)plaintext, input_len ) )
    {
        return NULL;
    }
    *ciphertext_len += bytes_written;
    
    //do padding
    if(!EVP_EncryptFinal_ex(&en, ciphertext + bytes_written, &bytes_written)){
        printf("ERROR in EVP_EncryptFinal_ex \n");
        return NULL;
    }
    *ciphertext_len += bytes_written;
    
    printf("encryption complete (%d->%d)\n", input_len, *ciphertext_len);
    
    EVP_CIPHER_CTX_cleanup(&en);
    return ciphertext;
}