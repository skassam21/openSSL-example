/* A SSL server that answers the secret question from the client

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

#define PORT 8765

#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "Incomplete shutdown"
#define KEYFILE "bob.pem"
#define PASSWORD "password"
#define CA_LIST "568ca.pem"

BIO *bio_err = 0;
static char *pass;
const char *allowedCiphers = "ALL";

static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

/* A simple error and exit routine*/
int err_exit(char* string)
{
  fprintf(stderr,"ECE568-SERVER: %s\n",string);
  exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char* string)
{
  BIO_printf(bio_err,"ECE568-SERVER: %s\n",string);
  ERR_print_errors(bio_err);
  exit(0);
}

/* Check that the server certificate is valid*/
void check_cert(SSL *ssl)
{
  X509 *peer;
  char peer_CN[256];
  char peer_email_address[256];

  peer=SSL_get_peer_certificate(ssl);

  if(SSL_get_verify_result(ssl)!=X509_V_OK || !peer)
    berr_exit("SSL accept error");

  X509_NAME_get_text_by_NID(
    X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

  X509_NAME_get_text_by_NID(
    X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email_address, 256);

  printf(FMT_CLIENT_INFO, peer_CN, peer_email_address);

}

static void sigpipe_handle(int x){
}

void destroy_ctx(SSL_CTX* ctx)
{
  SSL_CTX_free(ctx);
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
    meth=SSLv23_server_method();
    ctx=SSL_CTX_new(meth);
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

    // Have the server send the CA list to client to verify client
    // certificates
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CA_LIST));
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
      NULL);

    return ctx;
  }


void shutdown_server(SSL* ssl, int s) {
  int r;

  r=SSL_shutdown(ssl);
  if(!r){
    /* If we called SSL_shutdown() first then
       we always get return value of '0'. In
       this case, try again, but first send a
       TCP FIN to trigger the other side's
       close_notify*/
    shutdown(s,1);
    r=SSL_shutdown(ssl);
  }

  switch(r) {
    case 1:
      break; /* Success */
    case 0:
    case -1:
    default:
      berr_exit(FMT_INCOMPLETE_CLOSE);
  }
}


int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  BIO *sbio;
  SSL_CTX *ctx;
  SSL *ssl;
  int r;

  /* Build our SSL context*/
  ctx=initialize_ctx(KEYFILE,PASSWORD);

  /*Parse command line arguments*/

  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }

  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);

  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));

  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }

  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  }

  while(1){

    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }

    /*fork a child to handle the connection*/

    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      sbio=BIO_new_socket(s,BIO_NOCLOSE);
      ssl=SSL_new(ctx);
      SSL_set_bio(ssl,sbio,sbio);

      if((r=SSL_accept(ssl)<=0))
        berr_exit("SSL accept error");

      check_cert(ssl);

      int len;
      char buf[256];
      char *answer = "42";

      r = SSL_read(ssl, &buf, 255);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          buf[len]= '\0';

          printf(FMT_OUTPUT, buf, answer);
          r = SSL_write(ssl, answer, strlen(answer));
          switch(SSL_get_error(ssl,r)){
          case SSL_ERROR_NONE:
            if(strlen(answer)!=r)
              err_exit("Incomplete write");
            break;
            default:
              berr_exit("SSL write problem");
          }
          break;
        case SSL_ERROR_ZERO_RETURN:
          break;
        case SSL_ERROR_SYSCALL:
          err_exit(FMT_INCOMPLETE_CLOSE);
        default:
          berr_exit("SSL read problem");
      }


      shutdown_server(ssl, s);

      SSL_free(ssl);
      close(s);

      return 0;
    }
  }

  close(sock);
  destroy_ctx(ctx);
  return 1;
}
