/* A SSL client that asks a question the server and receives the answer
   from the server

   Author: Shums Kassam
   Sources: http://www.linuxjournal.com/article/4822
 */

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "localhost"
#define PORT 8765

#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "Server Common Name doesn't match"
#define FMT_EMAIL_MISMATCH "Server Email doesn't match"
#define FMT_NO_VERIFY "Certificate does not verify"
#define FMT_INCORRECT_CLOSE "Premature close"
#define KEYFILE "alice.pem"
#define PASSWORD "password"
#define CA_LIST "568ca.pem"
#define COMMON_NAME "Bob's Server"
#define EMAIL_ADDRESS "ece568bob@ecf.utoronto.ca"
#define ALLOWED_CIPHERS "SHA1"

BIO *bio_err = 0;
static char *pass;

/* Print an error and exit */
int error_exit(char *string)
{
  fprintf(stderr, "ECE568-CLIENT: %s\n", string);
  exit(0);
}

/* Print SSL errors and exit */
int bio_error_exit(char *string)
{
  BIO_printf(bio_err, "ECE568-CLIENT: %s\n", string);
  ERR_print_errors(bio_err);
  exit(0);
}

/* Check that the server certificate is valid */
void check_cert(SSL *ssl)
{
  X509 *peer;
  char peer_CN[256];
  char peer_email_address[256];
  char issuer[256];

  if(SSL_get_verify_result(ssl)!=X509_V_OK)
    bio_error_exit(FMT_NO_VERIFY);

  peer = SSL_get_peer_certificate(ssl);

  X509_NAME_get_text_by_NID(
    X509_get_issuer_name(peer), NID_commonName, issuer, 256);

  X509_NAME_get_text_by_NID(
    X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

  X509_NAME_get_text_by_NID(
    X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email_address, 256);

  /*Check the common name*/
  if(strcasecmp(peer_CN,COMMON_NAME)) {
    error_exit(FMT_CN_MISMATCH);
  }

  /*Check the email address*/
  if(strcasecmp(peer_email_address,EMAIL_ADDRESS)) {
    error_exit(FMT_EMAIL_MISMATCH);
  }

  // Certificate is valid
  printf(FMT_SERVER_INFO, peer_CN, peer_email_address, issuer);

}

static void sigpipe_handle(int x){
}

static int password_callback(char *buf, int num,
                             int rwflag, void *userdata)
{
  if(num < strlen(pass) + 1)
    return(0);

  strcpy(buf, pass);
  return(strlen(pass));
}

SSL_CTX *initialize_ctx(char *keyfile, char *password)
{
  const SSL_METHOD *meth;
  SSL_CTX *ctx;

  if(!bio_err) {
    SSL_library_init();
    SSL_load_error_strings();
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
  }

  signal(SIGPIPE,sigpipe_handle);

  /* Create ctx */
  meth=SSLv23_client_method();
  ctx=SSL_CTX_new(meth);

  /* Use only SSLv3 or TLSv1 (exclude SSLv2) */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  /* Only communicate with SHA1 server */
  SSL_CTX_set_cipher_list(ctx, ALLOWED_CIPHERS);

  /* Load keys and certificates */
  if(!(SSL_CTX_use_certificate_chain_file(ctx,
                                          keyfile)))
    bio_error_exit("Can't read certificate file");

  pass=password;
  SSL_CTX_set_default_passwd_cb(ctx,
                                password_callback);
  if(!(SSL_CTX_use_PrivateKey_file(ctx,
                                   keyfile,SSL_FILETYPE_PEM)))
    bio_error_exit("Can't read key file");

  /* Load the trusted certificates */
  if(!(SSL_CTX_load_verify_locations(ctx,
                                     CA_LIST,0)))
    bio_error_exit("Can't read CA list");

  return ctx;
}

void shutdown_client(SSL* ssl) {
  int r;
  r = SSL_shutdown(ssl);
  if(!r) {
    r=SSL_shutdown(ssl);
  }
  if (r != 1) {
    bio_error_exit(FMT_INCORRECT_CLOSE);          
  }
}

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  int r;
  char *host = HOST;
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";

  /*Parse command line arguments*/
  switch(argc) {
  case 1:
    break;
  case 3:
    host = argv[1];
    port=atoi(argv[2]);
    if (port<1||port>65535) {
      fprintf(stderr,"invalid port number");
      exit(0);
    }
    break;
  default:
    printf("Usage: %s server port\n", argv[0]);
    exit(0);
  }

  /*get ip address of the host*/
  host_entry = gethostbyname(host);

  if (!host_entry) {
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);

  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

  /* Initialize SSL context */
  ctx=initialize_ctx(KEYFILE, PASSWORD);

  /*open socket*/
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");

  /* Connect the SSL socket */
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);
  if(SSL_connect(ssl) <= 0)
    bio_error_exit("SSL connect error");
  
  /* check the certificate */  
  check_cert(ssl);

  /* send the secret question across */
  r=SSL_write(ssl, secret, strlen(secret));

  switch(SSL_get_error(ssl,r)) {
  case SSL_ERROR_NONE:
    if(strlen(secret)!=r)
      error_exit("Incomplete write");
    break;
  default:
    bio_error_exit("SSL write problem");
  }

  /* read the secret answer */
  r = SSL_read(ssl, &buf, 255);
  switch(SSL_get_error(ssl,r)) {
  case SSL_ERROR_NONE:
    len=r;
    buf[len]= '\0';

    printf(FMT_OUTPUT, secret, buf);
    break;
  case SSL_ERROR_ZERO_RETURN:
    break;
  case SSL_ERROR_SYSCALL:
    error_exit(FMT_INCORRECT_CLOSE);
  default:
    bio_error_exit("SSL read problem");
  }

  /* shutdown client and destroy ctx */
  shutdown_client(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(sock);

  return 1;
}
