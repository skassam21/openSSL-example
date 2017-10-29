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

/* use these strings to tell the marker what is happening */
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"
#define KEYFILE "alice.pem"
#define PASSWORD "password"
#define CA_LIST "568ca.pem"
#define COMMON_NAME "Bob's Server"
#define EMAIL_ADDRESS "ece568bob@ecf.utoronto.ca"

BIO *bio_err=0;
static char *pass;
const char *allowedCiphers = "SHA1+kRSA";

static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

void destroy_ctx(SSL_CTX* ctx)
{
  SSL_CTX_free(ctx);
}

/* A simple error and exit routine*/
int err_exit(string)
  char *string;
  {
    fprintf(stderr,"ECE568-CLIENT: %s\n",string);
    exit(0);
  }

/* Print SSL errors and exit*/
int berr_exit(char *string)
  {
    BIO_printf(bio_err,"ECE568-CLIENT: %s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
  }

/* Check that the server certificate is valid*/
void check_cert(SSL *ssl)
{
  X509 *peer;
  char peer_CN[256];
  char peer_email_address[256];
  char issuer[256];

  if(SSL_get_verify_result(ssl)!=X509_V_OK)
    berr_exit("Certificate does not verify");

  /*Check the common name*/
  peer=SSL_get_peer_certificate(ssl);

  X509_NAME_get_text_by_NID(
    X509_get_issuer_name(peer), NID_commonName, issuer, 256);

  X509_NAME_get_text_by_NID(
    X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

  X509_NAME_get_text_by_NID(
    X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email_address, 256);

  if(strcasecmp(peer_CN,COMMON_NAME)) {
    err_exit
      ("Server Common Name doesn't match");
  }
  if(strcasecmp(peer_email_address,EMAIL_ADDRESS)) {
    err_exit
      ("Server Email doesn't match");
  }

  // Certificate is valid
  printf(FMT_SERVER_INFO, peer_CN, peer_email_address, issuer);

}

static void sigpipe_handle(int x){
}

SSL_CTX *initialize_ctx(char *keyfile, char* password)
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();

      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);

    /* Create our context*/
    meth=SSLv23_client_method();
    ctx=SSL_CTX_new(meth);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_cipher_list(ctx, allowedCiphers);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx,
      keyfile)))
      berr_exit("Can't read certificate file");

    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx,
      password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      keyfile,SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx,
      CA_LIST,0)))
      berr_exit("Can't read CA list");

    return ctx;
  }

void shutdown_client(SSL* ssl) {
  int r;
  r=SSL_shutdown(ssl);
  if(!r){
    /* If we called SSL_shutdown() first then
       we always get return value of '0'. In
       this case, try again, but first send a
       TCP FIN to trigger the other side's
       close_notify*/
    r=SSL_shutdown(ssl);
  }

  switch(r){
    case 1:
      break; /* Success */
    case 0:
    case -1:
    default:
      berr_exit("Premature close");
  }
}

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  int r;
  char *host=HOST;
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";

  /*Parse command line arguments*/

  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
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

  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);

  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

  /* Build our SSL context*/
  ctx=initialize_ctx(KEYFILE,PASSWORD);

  /*open socket*/
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");

  /* Connect the SSL socket */
  ssl=SSL_new(ctx);
  sbio=BIO_new_socket(sock,BIO_NOCLOSE);
  SSL_set_bio(ssl,sbio,sbio);
  if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");
  check_cert(ssl);

  /* send the secret question across */
  r=SSL_write(ssl, secret, strlen(secret));
  switch(SSL_get_error(ssl,r)){
  case SSL_ERROR_NONE:
    if(strlen(secret)!=r)
      err_exit("Incomplete write");
    break;
    default:
      berr_exit("SSL write problem");
  }
  r = SSL_read(ssl, &buf, 255);
  switch(SSL_get_error(ssl,r)){
    case SSL_ERROR_NONE:
      len=r;
      buf[len]= '\0';

      printf(FMT_OUTPUT, secret, buf);
      break;
    case SSL_ERROR_ZERO_RETURN:
      break;
    case SSL_ERROR_SYSCALL:
      err_exit("Premature close");
    default:
      berr_exit("SSL read problem");
  }

  shutdown_client(ssl);
  SSL_free(ssl);
  destroy_ctx(ctx);
  close(sock);

  return 1;
}
