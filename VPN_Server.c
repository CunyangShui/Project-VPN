
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include <memory.h>
#include <errno.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "rstring.h"
#include "encryption.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define MAX_CHAR_SIZE 4096


struct Login {
    char *name;
    char *password;
};

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

struct Login readPWDFile(char *name)
{
    struct Login login;
    static char usr[20], pwd[100];
    char ch;
    int i = 0;
    FILE *fp;
    fp = fopen(name, "r");
    while((ch = fgetc(fp) ) != EOF )
    {
        usr[i] = ch;
        if (ch == ':')
        {
            usr[i] = '\0';
            break;
        }
        i++;
    }
    i = 0;
    while((ch = fgetc(fp)) != EOF )
    {
        pwd[i] = ch;
        i++;
    }
    pwd[i-1] = '\0';
    login.name = usr;
    login.password = pwd;
    
    return login;
}
void usage()
{
    fprintf(stderr, "Usage: tunproxy [-s port] [-e]\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    // Pipe initiate
    int     fd_pipe[2], nbytes;
    pid_t   childpid;
    char    readbuffer[200];
    // TCP Tunnel initiate
    int err;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    size_t client_len;
    SSL_CTX* ctx;
    SSL*     ssl;
    X509*    client_cert;
    char*    str;
    const SSL_METHOD *meth;
    
    // UDP Tunnel initiate
    unsigned char * out = NULL;
    unsigned char * final = NULL;
    unsigned char * iv = (unsigned char *)malloc(sizeof(unsigned char)*17);
    unsigned char * key_new = (unsigned char *)malloc(sizeof(unsigned char)*17);
    unsigned char * key_old = (unsigned char *)malloc(sizeof(unsigned char)*17);
    int ciphertext_len = 0;
    unsigned char ciphertext[MAX_CHAR_SIZE];
    unsigned char plaintext[MAX_CHAR_SIZE];
    
    struct sockaddr_in sin, sout, from;
    struct ifreq ifr;
    int fd, s, fromlen, soutlen, port, PORT, l;
    int i; // temp
    char c, *p, *ip;
    char buf[MAX_CHAR_SIZE];
    fd_set fdset;
    struct Login login;
    
    int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;
    
    // check arguments
    while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
        switch (c) {
            case 'h':
                usage();
            case 'd':
                DEBUG++;
                break;
            case 's':
                MODE = 1;
                PORT = atoi(optarg);
                break;
            case 'c':
                MODE = 2;
                p = memchr(optarg,':',16);
                if (!p) ERROR("invalid argument : [%s]\n",optarg);
                *p = 0;
                ip = optarg;
                port = atoi(p+1);
                PORT = 0;
                break;
            case 'e':
                TUNMODE = IFF_TAP;
                break;
            default:
                usage();
        }
    }
    if (MODE == 0) usage();
    
    /* SSL preliminaries. We keep the certificate and key with the context. */
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = SSLv23_server_method();
    ctx = SSL_CTX_new (meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    // Will not verify the client
    SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL); /* whether verify the certificate */
    // Set the location of the CA certificate
    SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
    
    // Prepare the certificate (the client will reuest it)
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        exit(5);
    }
    
    
    
    pipe2(fd_pipe, O_NONBLOCK);
    
    if((childpid = fork()) == -1)
    {
        perror("fork");
        exit(1);
    }
    
    if(childpid > 0)
    {
        // listen to interface
        if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");
        
        // set up new interface info
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = TUNMODE;
        strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
        if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");
        
        printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
        
        // allocte a new interface toto0
        s = socket(PF_INET, SOCK_DGRAM, 0);
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port = htons(PORT);
        if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");
        fromlen = sizeof(from);
        
        // server side waiting for a UDP connection
        while(1) {
            l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
            if (l < 0) PERROR("recvfrom");
            if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0)
                break;
            printf("Bad magic word from %s:%i\n",
                   (char *)inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
        }
        // once receive connect request, resend to check
        l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
        if (l < 0) PERROR("sendto");
        
        
        printf("Connection with %s:%i established\n",
               (char *)inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
        
        while (1)
        {
            FD_ZERO(&fdset);
            // fd is normal interface
            // s is UDP tunnel
            FD_SET(fd, &fdset);
            FD_SET(s, &fdset);
            
            if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
            
            strcpy(key_old, key_new);
            /* Parent process closes up output side of pipe */
            close(fd_pipe[1]);
            /* Read in a string from the pipe */
            nbytes = read(fd_pipe[0], readbuffer, sizeof(readbuffer));
            if (!strcmp("stop vpn", readbuffer))
            {
                close(fd);
                close(s);
                
                close(fd_pipe[0]);
                write(fd_pipe[1], "udp done", (strlen("udp done")+1));
                
                sleep(2);
                return 0;
            }
            if (strcmp("", readbuffer))
            {
                strcpy(key_new, readbuffer);
            }
            
            if (FD_ISSET(fd, &fdset))
            {
                if (DEBUG) write(1,">", 1);
                l = read(fd, buf, sizeof(buf));
                if (l < 0) PERROR("read");
                
                ciphertext_len = 0;
                randomString(iv, 16);
                
                
                out = encrypt_text(iv, key_new, buf, l, ciphertext, &ciphertext_len);

                for (i = 0; i < 16; i++){
                    out[ciphertext_len++] = iv[i];
                }
                // last 16 byte of out is iv
                if (sendto(s, out, ciphertext_len, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
                printf("Send packet in UDP tunnel use key - %s, iv - %s\n", key_new, iv);
            } else {
                if (DEBUG) write(1,"<", 1);
                l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
                //decryption here - buf
                
                l = l - 16;
                ciphertext_len = l;
                for(i = 0; i < 16; i++)
                {
                    iv[i] = buf[l++];
                }
                final = decrypt_text(iv, key_new, buf, &ciphertext_len, plaintext, &l);
                if (l == 0)
                {
                    final = decrypt_text(iv, key_old, buf, &ciphertext_len, plaintext, &l);
                    if(l == 0)
                    {
                        strcpy(key_old, key_new);
                        /* Parent process closes up output side of pipe */
                        close(fd_pipe[1]);
                        /* Read in a string from the pipe */
                        nbytes = read(fd_pipe[0], readbuffer, sizeof(readbuffer));
                        if (!strcmp("stop vpn", readbuffer))
                        {
                            close(fd);
                            close(s);
                        
                            close(fd_pipe[0]);
                            write(fd_pipe[1], "udp done", (strlen("udp done")+1));
                        
                            sleep(2);
                            return 0;
                        }
                        final = decrypt_text(iv, key_new, buf, &ciphertext_len, plaintext, &l);
                        if (strcmp("", readbuffer))
                        {
                            strcpy(key_new, readbuffer);
                        }
                    }
                }
                printf("Get packet in UDP tunnel use key - %s, iv - %s\n", key_new, iv);
                //
                if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
                    printf("Got packet from  %s:%i instead of %s:%i\n",
                           (char *)inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
                           (char *)inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
                if (write(fd, final, l) < 0) PERROR("write");
            }
        }
    }
    else
    {
        /* ----------------------------------------------- */
        /* Prepare TCP socket for receiving connections */
        
        listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
        
        memset (&sa_serv, '\0', sizeof(sa_serv));
        sa_serv.sin_family      = AF_INET;
        sa_serv.sin_addr.s_addr = INADDR_ANY;
        sa_serv.sin_port        = htons (6068);          /* Server Port number */
        
        err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv));
        CHK_ERR(err, "bind");
        
        /* Receive a TCP connection. */
        
        err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
        
        client_len = sizeof(sa_cli);
        sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
        CHK_ERR(sd, "accept");
        close (listen_sd);
        
        printf("TCP connection from %s, port %d\n",
               (char *)inet_ntoa(sa_cli.sin_addr.s_addr), ntohs(sa_cli.sin_port));
        
        /* ----------------------------------------------- */
        /* TCP connection is ready. Do server side SSL. */
        
        ssl = SSL_new (ctx);                           CHK_NULL(ssl);
        SSL_set_fd (ssl, sd);
        err = SSL_accept (ssl);                        CHK_SSL(err);
        
        /* Get the cipher - opt */
        
        printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
        
        /* Get client's certificate (note: beware of dynamic allocation) - opt */
        
        client_cert = SSL_get_peer_certificate (ssl);
        if (client_cert != NULL) {
            printf ("Client certificate:\n");
            
            str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
            CHK_NULL(str);
            printf ("\t subject: %s\n", str);
            OPENSSL_free (str);
            
            str = X509_NAME_oneline (X509_get_issuer_name (client_cert), 0, 0);
            CHK_NULL(str);
            printf ("\t issuer: %s\n", str);
            OPENSSL_free (str);
            
            /* We could do all sorts of certificate verification stuff here before
             deallocating the certificate. */
            
            X509_free (client_cert);
        } else
            printf ("Client does not have certificate.\n");
        
        
        login = readPWDFile("password");
        err = SSL_read (ssl, buf, sizeof(buf) - 1);
        CHK_SSL(err);
        buf[err] = '\0';
        if (strcmp(login.name, buf)){
            printf("user doesn't exist\n");
            err = SSL_write (ssl, "reject connection", strlen("reject connection"));
            CHK_SSL(err);
        }
        
        err = SSL_read (ssl, buf, sizeof(buf) - 1);
        CHK_SSL(err);
        buf[err] = '\0';
        if (!strcmp(login.password, (char *)crypt(buf, "$5$ImSalt")))
        {
            printf("pass password verification\n");
            err = SSL_write (ssl, "allow connection", strlen("allow connection"));
            CHK_SSL(err);
        } else {
            printf("not pass password verification\n");
            err = SSL_write (ssl, "reject connection", strlen("reject connection"));
            CHK_SSL(err);
        }
        memset(&buf, 0, sizeof(buf));
        memset(&login, 0, sizeof(login));
        
        while (1)
        {
            /* Child process closes up input side of pipe */
            close(fd_pipe[0]);
            randomString(key_new, 16);
            write(fd_pipe[1], key_new, (strlen(key_new)+1));
            err = SSL_write (ssl, key_new, strlen(key_new));
            CHK_SSL(err);
            printf("update key in TCP tunnel: %s\n", key_new);
            
            err = SSL_read (ssl, buf, sizeof(buf) - 1);
            CHK_SSL(err);
            buf[err] = '\0';
            if (!strcmp("stop vpn", buf))
            {
                printf("Receive stop command\n");
                
                close(sd);
                
                close(fd_pipe[1]);
                read(fd_pipe[0], buf, (strlen(buf)+1));

                
                while(1){
                    close(fd_pipe[0]);
                    write(fd_pipe[1], "stop vpn", (strlen("stop vpn")+1));
                    sleep(1);
                    close(fd_pipe[1]);
                    read(fd_pipe[0], buf, (strlen(buf)+1));
                    if (!strcmp("udp done", buf)){
                        /* Clean up. */
                        SSL_free(ssl);
                        SSL_CTX_free(ctx);
                        return 0;
                    }
                }

                
            }
            
            sleep(1);
        }
    }
}

