#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "ddnsclient.h"

static int
encode_base64(char *encoded, int outputlen, const char *input, int len)
{
	BIO *bio, *b64;
	BUF_MEM *buffer;

	b64 = BIO_new(BIO_f_base64()); assert(b64);

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines

	bio = BIO_new(BIO_s_mem()); assert(bio);
	bio = BIO_push(b64, bio);

	assert(BIO_write(bio, input, len) == len);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &buffer);
	int resultlen = buffer->length;

	if(outputlen <= resultlen) return -1;

	memcpy(encoded, buffer->data, resultlen);
	encoded[buffer->length] = '\0';	//Zero-terminate

	BIO_free_all(bio);

	return buffer->length; //success
}

void
send_update_request(const char *hostname, const char* myip, const char *username, const char* password)
{
	const SSL_METHOD *method = SSLv23_client_method();
	SSL_CTX *ctx;

	SSL_load_error_strings();
	SSL_library_init();
	ctx = SSL_CTX_new(method);

	//TCP socket
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	host = gethostbyname(hostname);
	sd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(443);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	assert(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) == 0);

	//Start SSL session
	SSL *ssl;
	ssl = SSL_new(ctx);    // create new SSL connection state
	SSL_set_fd(ssl, sd);   // attach the socket descriptor
	SSL_connect(ssl);          // perform the connection

	//Create request
	size_t auth_size = (strlen(username) + strlen(password) + 1);
	char auth[auth_size + 1];
	assert(sprintf(auth, "%s:%s", username, password) <= auth_size);

	size_t encoded_size = 4 * ((auth_size + 2) / 3) + 1;
	char encoded_auth[encoded_size];

	encode_base64(encoded_auth, encoded_size, auth, auth_size);

	//Request format for dyndns-like protocol
	const char *format = "GET /?myip=%s HTTP/1.0\r\nAuthorization: Basic %s\r\nHost: %s\r\nConnection: Close\r\n\r\n";
	int request_size = snprintf(NULL, 0, format, myip, encoded_auth, hostname);

	char request[request_size + 1];
	snprintf(request, request_size + 1, format, myip, encoded_auth, hostname);

	SSL_write(ssl, request, request_size);

	//Read answer
	int BUFFERLEN = 16384;
	char buffer[BUFFERLEN];
	char *p = buffer;
	int len;

	//TODO: Parse return value and answer
	while ((len = SSL_read(ssl, p, BUFFERLEN - (p - buffer) - 1)) > 0)
	{
		p += len;
		assert(p - buffer < BUFFERLEN - 1); //TODO: Keep receiving and throw away?
	}

	*p = '\0';

	//Print response
	log("RESPONSE:\n%s<END OF RESPONSE>\n", buffer);

	int shutdown_state = SSL_shutdown(ssl);
	if (shutdown_state == 0)
	{
		verbose_log("Shutdown state: 0\n");
		shutdown_state = SSL_shutdown(ssl);
	}
	else if(shutdown_state < 0)
	{
		verbose_log("Shutdown failed: SSL_get_error: %d\n", SSL_get_error(ssl, shutdown_state));
	}

	verbose_log("Shutdown state (get_shutdown()): %d\n", SSL_get_shutdown(ssl));

	//TODO: Parse response?

	SSL_free(ssl);              /* release SSL state */
	SSL_CTX_free(ctx);

	CRYPTO_cleanup_all_ex_data();

	close(sd);
}