#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <ctype.h>
#define FAIL    -1

#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

// Create the SSL socket and intialize the socket address structure
int create_socket(int port)
{
    int sockfd;
    struct sockaddr_in addr;
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("ERROR in BIND ");
        abort();
    }
    if ( listen(sockfd, 10) != 0 )
    {
        perror("ERROR in listen");
        abort();
    }
    return sockfd;
}
SSL_CTX* ssl_init(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void send_certificate(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void verify_certs(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Client certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        long res = SSL_get_verify_result(ssl);
        if(res == 0){
            printf("Certificate Verified\n");
        }
        else{
            printf("Error in verifying certificate as: %ld\n",res);
        }
        free(line);
        X509_free(cert);
    }
    else
        printf("Info: No client certificates configured\n");
}
void send_reply(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] ,reply[1024];
    int sockfd, bytes;
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        verify_certs(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
              /* construct reply */
            for (int i = 0; i < strlen(buf); i++)
            {
                reply[i] = toupper(buf[i]);
            }
            SSL_write(ssl, reply, strlen(buf)); /* send reply */
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    sockfd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sockfd);          /* close connection */
}
int main(int argsc, char *args[])
{

    if ( argsc != 2 )
    {
        printf("Usage: %s <portnum>\n", args[0]);
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();
    char *portnum = args[1];
    SSL_CTX *ctx = ssl_init();        /* initialize SSL */
    send_certificate(ctx, "server-cert.pem", "server-key.pem"); /* load certs */
    int server = create_socket(atoi(portnum));    /* create server socket */
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        /* Start verification */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 5);
        const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        long old_opts = SSL_CTX_set_options(ctx, flags);
        UNUSED(old_opts);
        int res = SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", "ca-key.pem");
        if(!(1 == res))
        {
            perror("SSL_CTX_load_verify_locations");
        }

        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        send_reply(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}