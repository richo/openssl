#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


// Simple structure to keep track of the handle, and
// of what needs to be freed later.
typedef struct {
    int socket;
    SSL *sslHandle;
    SSL_CTX *sslContext;
} connection;

// For this example, we'll be testing on openssl.org
#define SERVER  "openssl.org"
#define PORT 443
/* #define PORT 10023 */

// Establish a regular tcp connection
int tcpConnect (const char* hostname, int* port)
{
  int error, handle;
  struct hostent *host;
  struct sockaddr_in server;

  host = gethostbyname (hostname);
  handle = socket (AF_INET, SOCK_STREAM, 0);
  if (handle == -1)
    {
      perror ("Socket");
      handle = 0;
    }
  else
    {
      server.sin_family = AF_INET;
      if (port)
          server.sin_port = htons(*port);
      else
          server.sin_port = htons(PORT);
      server.sin_addr = *((struct in_addr *) host->h_addr);
      bzero (&(server.sin_zero), 8);

      error = connect (handle, (struct sockaddr *) &server,
                       sizeof (struct sockaddr));
      if (error == -1)
        {
          perror ("Connect");
          handle = 0;
        }
    }

  return handle;
}

// Establish a connection using an SSL layer
connection *sslConnect (const char* hostname, int* port)
{
  connection *c;

  c = malloc (sizeof (connection));
  c->sslHandle = NULL;
  c->sslContext = NULL;


  c->socket = tcpConnect (hostname, port);
  if (c->socket)
    {
      // Register the error strings for libcrypto & libssl
      SSL_load_error_strings ();
      // Register the available ciphers and digests
      SSL_library_init ();

      // New context saying we are a client, and using SSL 2 or 3
      c->sslContext = SSL_CTX_new (SSLv23_client_method ());
      if (c->sslContext == NULL)
        ERR_print_errors_fp (stderr);

      // Create an SSL struct for the connection
      c->sslHandle = SSL_new (c->sslContext);
      if (c->sslHandle == NULL)
        ERR_print_errors_fp (stderr);

      // Connect the SSL struct to our connection
      if (!SSL_set_fd (c->sslHandle, c->socket))
        ERR_print_errors_fp (stderr);

      // Initiate SSL handshake
      if (SSL_connect (c->sslHandle) != 1)
        ERR_print_errors_fp (stderr);
    }
  else
    {
      perror ("Connect failed");
    }

  return c;
}

// Disconnect & free connection struct
void sslDisconnect (connection *c)
{
  if (c->socket)
    close (c->socket);
  if (c->sslHandle)
    {
      SSL_shutdown (c->sslHandle);
      SSL_free (c->sslHandle);
    }
  if (c->sslContext)
    SSL_CTX_free (c->sslContext);

  free (c);
}

// Read all available text from the connection
char *sslRead (connection *c)
{
  const int readSize = 1024;
  char *rc = NULL;
  int received, count = 0;
  char buffer[1024];

  if (c)
    {
      while (1)
        {
          if (!rc)
            rc = malloc (readSize * sizeof (char) + 1);
          else
            rc = realloc (rc, (count + 1) *
                          readSize * sizeof (char) + 1);

          received = SSL_read (c->sslHandle, buffer, readSize);
          buffer[received] = '\0';

          if (received > 0)
            strcat (rc, buffer);

          if (received < readSize)
            break;
          count++;
        }
    }

  return rc;
}

// Write text to the connection
void sslWrite (connection *c, char *text)
{
  if (c)
    SSL_write (c->sslHandle, text, strlen (text));
}

int flatDucks(SSL *s);


// Very basic main: we send GET / and print the response.
int main (int argc, char **argv)
{
  connection *c;
  char *response;
  int ret, port = 0;

  if (argc > 2) {
      port = atoi(argv[2]);
  }

  if (port == 0)
      port = PORT;

  if (argc > 1) {
      c = sslConnect(argv[1], &port);
  } else {
      c = sslConnect(SERVER, &port);
  }


  fprintf(stderr, "&s->method->ssl_write: %p\n", (c->sslHandle->method->ssl_write));
  fprintf(stderr, "&s->method->ssl_write_bytes: %p\n", (c->sslHandle->method->ssl_write));

  ret = SSL_heartbeat(c->sslHandle);
  fprintf(stderr, "Got %d\n", ret);


  /* ret = tls1_heartbeat(c->sslContext); */
  /* fprintf(stderr, "Got %d\n", ret); */

  /* ret = flatDucks(c->sslHandle); */
  /* fprintf(stderr, "Got %d\n", ret); */

  fprintf(stderr, "[+] Sending dummy payload to trigger our heartbeat\n");
  sslWrite (c, "GET / HTTP/1.1\r\n\r\n");
  response = sslRead (c);
  if (strlen(response) > 32) {
      response[32] = 0x00;
  }

  printf ("[<] %s\n", response);
  fflush(stdout);

  fprintf(stderr, "-----\n\n");

  sslDisconnect (c);
  free (response);

  return 0;
}
