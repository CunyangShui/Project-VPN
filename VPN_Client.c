
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

#include <memory.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "rstring.h"
#include "encryption.h"
#include "pwdinput.h"

#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define EVP_DES_CBC EVP_des_cbc()
#define MAX_CHAR_SIZE 4096

void *readcharinput(void *inputchar){
    char *char1;
    char1 = (char *)inputchar;
    while(1)
    {
        scanf("%s", char1);
        getchar(); // return
        if (*char1 == 's')
            break;
    }
}

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

void usage()
{
	fprintf(stderr, "Usage: tunproxy [-c targetip:port] [-e]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
    int     fd_pipe[2], nbytes;
    pid_t   childpid;
    char    readbuffer[200];
    
    // TCP Tunnel initiate
    int err;
    int sd;
    struct sockaddr_in sa;
    SSL_CTX* ctx;
    SSL*     ssl;
    X509*    server_cert;
    char*    str;
    char     string[] = "Hello World! 0";
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
    int nid_cn = OBJ_txt2nid("CN");
    char common_name[256];
    char * CMMAME = (unsigned char *)malloc(sizeof(unsigned char)*30);
	fd_set fdset;

	int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;

	while ((c = getopt(argc, argv, "s:c:n:ehd")) != -1) {
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
        case 'n':
            CMMAME = optarg;
            break;
		default:
			usage();
		}
	}
	if (MODE == 0) usage();
    
    /* SSL preliminaries. We keep the certificate and key with the context. */
    SSLeay_add_ssl_algorithms();
    meth = SSLv23_client_method(); //client
    SSL_load_error_strings();
    ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);
    
    CHK_SSL(err);
    
    // Will verify the server
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    // Set the location of the CA certificate
    SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

/////    This part is client side authentication, not expect to do that (private key: shuiclient)
//    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stderr);
//        exit(-2);
//    }
//    
//    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stderr);
//        exit(-3);
//    }
//    
//    if (!SSL_CTX_check_private_key(ctx)) {
//        printf("Private key does not match the certificate public keyn");
//        exit(-4);
//    }

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
        
        // client side send connect request to server
        from.sin_family = AF_INET;
        from.sin_port = htons(port);
        inet_aton(ip, &from.sin_addr);
        
        //waiting for server connect permission
        while(1){
            /* Parent process closes up output side of pipe */
            close(fd_pipe[1]);
            /* Read in a string from the pipe */
            nbytes = read(fd_pipe[0], readbuffer, sizeof(readbuffer));
            if (!strcmp("allow connection", readbuffer))
                break;
            if (!strcmp("reject connection", readbuffer))
                return 0;
        }
        
        l =sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
        if (l < 0) PERROR("sendto");
        // verify server
        l = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (l < 0) PERROR("recvfrom");
        if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0))
            ERROR("Bad magic word for peer\n");
        
        printf("Connection with %s:%i established\n",
               (char *)inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
        
        while (1){
            
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
            
            if (FD_ISSET(fd, &fdset)) {
                
                if (DEBUG) write(1,">", 1);
                l = read(fd, buf, sizeof(buf));
                if (l < 0) PERROR("read");

                ciphertext_len = 0;
                randomString(iv, 16);
                
                out = encrypt_text(iv, key_new, buf, l, ciphertext, &ciphertext_len);
                
                // last 16 byte of out is iv
                for (i = 0; i < 16; i++){
                    out[ciphertext_len++] = iv[i];
                }
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
        /* Create a socket and connect to server using normal socket calls. */
        
        sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
        
        memset (&sa, '\0', sizeof(sa));
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = inet_addr ("10.0.2.11");   /* Server IP */
        sa.sin_port        = htons     (6068);          /* Server Port number */
        
        err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
        CHK_ERR(err, "connect");
        
        /* ----------------------------------------------- */
        /* Now we have TCP conncetion. Start SSL negotiation. */
        // ctx -> ssl secure socket
        ssl = SSL_new (ctx);                         CHK_NULL(ssl);
        SSL_set_fd (ssl, sd);
        err = SSL_connect (ssl);                     CHK_SSL(err);
        
        /* Following two steps are optional and not required for
         data exchange to be successful. */
        
        /* Get the cipher - opt */
        
        printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
        
        /* Get server's certificate (note: beware of dynamic allocation) - opt */
        
        server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
        printf ("Server certificate:\n");
        
        str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
        CHK_NULL(str);
        printf ("\t subject: %s\n", str);
        OPENSSL_free (str);
        
        str = X509_NAME_oneline (X509_get_issuer_name (server_cert),0,0);
        CHK_NULL(str);
        printf ("\t issuer: %s\n", str);
        OPENSSL_free (str);
        
        //check common name here
        X509_NAME_get_text_by_NID(X509_get_subject_name (server_cert), nid_cn, common_name, 256);
        if(!strcmp(CMMAME, common_name))
        {
            printf("common name verification success\n");
            
        } else {
            printf("common name verification fail\n");
            return 0;
        }
        
        /* We could do all sorts of certificate verification stuff here before
         deallocating the certificate. */
        
        X509_free (server_cert);
        
        /* type in usrname and password begin */
        char password[20], usrname[20];
        printf("Please input user name:");
        scanf("%s",usrname);
        getchar(); // return
        
        set_disp_mode(STDIN_FILENO,0);
        getpasswd(password, sizeof(password));
        p = password;
        while(*p!='\n')
            p++;
        *p='\0';
        set_disp_mode(STDIN_FILENO,1);
        /* type in usrname and password end */
        printf("\n");
                err = SSL_write (ssl, usrname, strlen(usrname));
        CHK_SSL(err);
        
        err = SSL_write (ssl, password, strlen(password));
        CHK_SSL(err);
        /* zero-out password memory */
        memset(&password, 0, sizeof(char)*20);
        memset(&usrname, 0, sizeof(char)*20);
        
        err = SSL_read (ssl, buf, sizeof(buf) - 1);
        CHK_SSL(err);
        buf[err] = '\0';
        if(!strcmp("allow connection", buf))
        {
            /* Child process closes up input side of pipe */
            close(fd_pipe[0]);
            write(fd_pipe[1], buf, (strlen(buf)+1));
   
        } else {
            close(fd_pipe[0]);
            write(fd_pipe[1], buf, (strlen(buf)+1));
            
            close (sd);
            SSL_free (ssl);
            SSL_CTX_free (ctx);
            printf ("Wrong user name and password\n");
            return 0;
        }
        
        pthread_t thread1;
        static char stopchar;
        int iret = pthread_create(&thread1, NULL, readcharinput, (void *)&stopchar);
        if (iret){
            printf("add thread wrong\n");
        }
//        pthread_join(thread1, NULL);
        
        while (1){
            err = SSL_read (ssl, buf, sizeof(buf) - 1);
            CHK_SSL(err);
            buf[err] = '\0';
            printf ("Receive key in TCP tunnel: %s\n", buf);

            /* Child process closes up input side of pipe */
            close(fd_pipe[0]);
            
            /* Send "string" through the output side of pipe */
            write(fd_pipe[1], buf, (strlen(buf)+1));
            
            err = SSL_write (ssl, "key received", strlen("key received"));
            CHK_SSL(err);
            
            
            if (stopchar == 's')
            {
                printf ("Receive stop command\n");
                err = SSL_write (ssl, "stop vpn", strlen("key received"));
                CHK_SSL(err);
                
                close(sd);

                close(fd_pipe[1]);
                read(fd_pipe[0], buf, (strlen(buf)+1));

   
                stopchar = '\0';
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
        }
    }
}

