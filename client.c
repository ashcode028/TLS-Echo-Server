#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#define FAIL    -1

#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

int connect_socket(const char *hostname, int port)
{
    int socketfd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    socketfd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(socketfd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(socketfd);
        perror(hostname);
        abort();
    }
    return socketfd;
}
SSL_CTX* ssl_init(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
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

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        long res = SSL_get_verify_result(ssl);
        if(res == 0){
            printf("Certificate Verified\n");
        }
        else{
            printf("Error in verifying certificate as: %ld\n",res);
        }
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No server certificates configured.\n");
}
int main(int argsc, char *args[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;
    if ( argsc != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", args[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=args[1];
    portnum=args[2];
    ctx = ssl_init();
    send_certificate(ctx, "client-cert.pem", "client-key.pem");
    server = connect_socket(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 5);
    const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    long old_opts = SSL_CTX_set_options(ctx, flags);
    UNUSED(old_opts);

    int res = SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", "ca-key.pem");
    if(!(1 == res))
    {
        /* Non-fatal, but something else will probably break later */
        perror("SSL_CTX_load_verify_locations");
    }
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        char *msg = "Hello sockets world";
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        verify_certs(ssl);        /* get any certs */
        SSL_write(ssl,msg, strlen(msg));   /* encrypt & send message */
        printf("Sent:%s\n", msg);
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received:%s\n", buf);
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}