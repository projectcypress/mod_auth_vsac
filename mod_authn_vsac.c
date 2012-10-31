/*****************************************************************************
 * mod_authn_vsac
 *
 * This apache module implements a Basic Authentication Provider that will
 * authenticate a user by invoking the NLM VSAC RESTful authentication.
 * service.  The need for this module is an unfortunate side-effect of NLM
 * deciding that they needed a REST API in front of a CAS server :(
 *
 * Author: Tim Taylor <ttaylor@mitre.org>
 * Date: 25 Oct. 2012
 ****************************************************************************/

#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_provider.h"
#include "http_log.h"
#include "mod_auth.h"
#include "apr_strings.h"
#include "apr_xml.h"

#include "mod_authn_vsac.h"

/* utility function to set/retrieve values from the configuration */
static apr_byte_t vsac_setURL(apr_pool_t *p, apr_uri_t *uri, const char *url)
{
  if(url == NULL) {
    /* uri = apr_pcalloc(p, sizeof(apr_uri_t)); */
    memset(uri, '\0', sizeof(apr_uri_t));
    return FALSE;
  }

  if(apr_uri_parse(p, url, uri) != APR_SUCCESS)
    return FALSE;

  /* set a default port if none was specified - we need this to perform a connect() to these servers later */
  if(uri->port == 0)
    uri->port = apr_uri_port_of_scheme(uri->scheme);
  if(uri->hostname == NULL)
    return FALSE;

  return TRUE;
}

static apr_byte_t isRequestSSL(request_rec *r) {
#ifdef APACHE2_0
  if(apr_strnatcasecmp("https", ap_http_method(r)) == 0)
#else
  if(apr_strnatcasecmp("https", ap_http_scheme(r)) == 0)
#endif
    return TRUE;

  return FALSE;
}

static apr_byte_t isSSL(apr_uri_t *uri)
{
  if(NULL == uri || apr_strnatcasecmp("https", uri->scheme))
    return FALSE;

  return TRUE;
}

static const char *cfg_readVSACParameter(cmd_parms *cmd, void *cfg, const char *value)
{
  vsac_cfg *c =
    (vsac_cfg *) ap_get_module_config(cmd->server->module_config,
                                      &authn_vsac_module);
  apr_finfo_t f;
  int i;
  
  if(NULL == c) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server, "MOD_AUTHN_VSAC: Oops! config is NULL in cfg_readVSACParameter!");
    return NULL;
  }

  /* cases determined from valid_cmds in mod_authn_vsac.h - the config at this
   * point is initialized to default values */
  switch((size_t) cmd->info) {
    case cmd_uservalidate_url:
      if(vsac_setURL(cmd->pool, &(c->vsac_uservalidate_url), value) != TRUE)
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: User validate URL '%s' could not be parsed!", value));
      break;
    case cmd_proxy_port:
      i = atoi(value);
      if(i > 0)
        c->vsac_proxy_port = i;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Invalid proxy port (%s) specified", value));
      break;
    case cmd_proxy_host:
      c->vsac_proxy_host = apr_pstrdup(cmd->pool, value);
      break;
    case cmd_debug:
      /* if atoi() is used on value here with AP_INIT_FLAG, it works but results in a compile warning, so we use TAKE1 to avoid it */
      if(apr_strnatcasecmp(value, "On") == 0)
        c->vsac_debug = TRUE;
      else if(apr_strnatcasecmp(value, "Off") == 0)
        c->vsac_debug = FALSE;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Invalid argument to VSACDebug - must be 'On' or 'Off'"));
      break;
    case cmd_validate_server:
      if(apr_strnatcasecmp(value, "On") == 0)
        c->vsac_validate_server = TRUE;
      else if(apr_strnatcasecmp(value, "Off") == 0)
        c->vsac_validate_server = FALSE;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Invalid argument to VSACValidateServer - must be 'On' or 'Off'"));
      break;
    case cmd_ca_path:
      if(apr_stat(&f, value, APR_FINFO_TYPE, cmd->temp_pool) == APR_INCOMPLETE)
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Could not find Certificate Authority file '%s'", value));

      if(f.filetype != APR_REG && f.filetype != APR_DIR)
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Certificate Authority file '%s' is not a regular file or directory", value));
      c->vsac_certificate_path = apr_pstrdup(cmd->pool, value);
      break;
    case cmd_validate_depth:
      i = atoi(value);
      if(i > 0)
        c->vsac_validate_depth = i;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Invalid VSACValidateDepth (%s) specified", value));
      break;
    case cmd_wildcard_cert:
      if(apr_strnatcasecmp(value, "On") == 0)
        c->vsac_allow_wildcard_cert = TRUE;
      else if(apr_strnatcasecmp(value, "Off") == 0)
        c->vsac_allow_wildcard_cert = FALSE;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Invalid argument to VSACAllowWildcardCert - must be 'On' or 'Off'"));
      break;
    case cmd_use_proxy:
      if(apr_strnatcasecmp(value, "On") == 0)
        c->vsac_use_proxy = TRUE;
      else if(apr_strnatcasecmp(value, "Off") == 0)
        c->vsac_use_proxy = FALSE;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: Invalid argument to VSACUseProxy - must be 'On' or 'Off'"));
      break;
    default:
      /* should not happen */
      return(apr_psprintf(cmd->pool, "MOD_AUTHN_VSAC: invalid command '%s'", cmd->directive->directive));
      break;
  }
  return NULL;
}

static char *getVSACValidateURL(request_rec *r, vsac_cfg *c, unsigned flags)
{
  apr_uri_t test;

  memset(&test, '\0', sizeof(apr_uri_t));
  if(memcmp(&c->vsac_uservalidate_url, &test, sizeof(apr_uri_t)) == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: VSACUserValidateURL null (not set)?");
    return NULL;
  }
  return(apr_uri_unparse(r->pool, &(c->vsac_uservalidate_url), flags));
}

static void *vsac_create_server_config(apr_pool_t *p, server_rec *svr)
{
  vsac_cfg *c = apr_pcalloc(p, sizeof(vsac_cfg));

  c->vsac_use_proxy = VSAC_DEFAULT_USE_PROXY;
  c->vsac_proxy_host = VSAC_DEFAULT_PROXY_HOST;
  c->vsac_proxy_port = VSAC_DEFAULT_PROXY_PORT;
  c->vsac_debug = VSAC_DEFAULT_DEBUG;
  c->vsac_validate_server = VSAC_DEFAULT_VALIDATE_SERVER;
  c->vsac_validate_depth = VSAC_DEFAULT_VALIDATE_DEPTH;
  c->vsac_certificate_path = VSAC_DEFAULT_CA_PATH;
  c->vsac_allow_wildcard_cert = VSAC_DEFAULT_ALLOW_WILDCARD_CERT;

  vsac_setURL(p, &(c->vsac_uservalidate_url), VSAC_DEFAULT_USERVALIDATE_URL);
  return c;
}

static void *vsac_merge_server_config(apr_pool_t *p, void *BASE, void *ADD)
{
  vsac_cfg *c = apr_pcalloc(p, sizeof(vsac_cfg));
  vsac_cfg *base = BASE;
  vsac_cfg *add = ADD;
  apr_uri_t test;
  memset(&test, '\0', sizeof(apr_uri_t));

	c->vsac_use_proxy = (add->vsac_use_proxy != VSAC_DEFAULT_USE_PROXY ? add->vsac_use_proxy : base->vsac_use_proxy);
	c->vsac_proxy_host = (add->vsac_proxy_host != VSAC_DEFAULT_PROXY_HOST ? add->vsac_proxy_host : base->vsac_proxy_host);
	c->vsac_proxy_port = (add->vsac_proxy_port != VSAC_DEFAULT_PROXY_PORT ? add->vsac_proxy_port : base->vsac_proxy_port);
	c->vsac_debug = (add->vsac_debug != VSAC_DEFAULT_DEBUG ? add->vsac_debug : base->vsac_debug);
	c->vsac_allow_wildcard_cert = (add->vsac_allow_wildcard_cert != VSAC_DEFAULT_ALLOW_WILDCARD_CERT ? add->vsac_allow_wildcard_cert : base->vsac_allow_wildcard_cert);
	c->vsac_validate_server = (add->vsac_validate_server != VSAC_DEFAULT_VALIDATE_SERVER ? add->vsac_validate_server : base->vsac_validate_server);
	c->vsac_validate_depth = (add->vsac_validate_depth != VSAC_DEFAULT_VALIDATE_DEPTH ? add->vsac_validate_depth : base->vsac_validate_depth);
	c->vsac_certificate_path = ((strcmp(add->vsac_certificate_path, VSAC_DEFAULT_CA_PATH) != 0) ? add->vsac_certificate_path : base->vsac_certificate_path);

  /* if add->vsac_uservalidate_url == NULL, we want to copy base -- otherwise, copy the one from add, and so on and so forth */
	if(memcmp(&add->vsac_uservalidate_url, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->vsac_uservalidate_url, &base->vsac_uservalidate_url, sizeof(apr_uri_t));
	else
		memcpy(&c->vsac_uservalidate_url, &add->vsac_uservalidate_url, sizeof(apr_uri_t));

  return c;
}

static void *vsac_create_dir_config(apr_pool_t *p, char *d)
{
  vsac_dir_cfg *c = apr_pcalloc(p, sizeof(vsac_dir_cfg));

  c->vsac_license_code = VSAC_DEFAULT_LICENSE_CODE;
  return c;
}

static void *vsac_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD)
{
	vsac_dir_cfg *c = apr_pcalloc(pool, sizeof(vsac_dir_cfg));
	vsac_dir_cfg *base = BASE;
	vsac_dir_cfg *add = ADD;

	/* inherit the previous directory's setting if applicable */
	c->vsac_license_code = (add->vsac_license_code != VSAC_DEFAULT_LICENSE_CODE ? add->vsac_license_code : base->vsac_license_code);

  return c;
}

static void VSACCleanupSocket(socket_t s, SSL *ssl, SSL_CTX *ctx)
{
  if(s != INVALID_SOCKET)
#ifdef WIN32
    closesocket(s);
#else
    close(s);
#endif

  if(ssl != NULL)
    SSL_free(ssl);

  if(ctx != NULL)
    SSL_CTX_free(ctx);

#ifdef WIN32
  WSACleanup();
#endif
  return;
}

/* SSL specific functions - these should be replaced by the APR-1.3 SSL functions when they are available */
/* Credit to Shawn Bayern for the basis of most of this SSL related code */
static apr_byte_t check_cert_cn(request_rec *r, vsac_cfg *c, SSL_CTX *ctx, X509 *certificate, char *cn)
{
  char buf[512];
  char *domain = cn;
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  X509_STORE_CTX *xctx = X509_STORE_CTX_new();

  if(c->vsac_debug)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering check_cert_cn()");
  /* specify that 'certificate' (what was presented by the other side) is what we want to verify against 'store' */
  X509_STORE_CTX_init(xctx, store, certificate, sk_X509_new_null());

  /* this may be redundant, since we require peer verification to perform the handshake */
  if(X509_verify_cert(xctx) == 0)
    return FALSE;

  X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_commonName, buf, sizeof(buf) - 1);
  if(c->vsac_debug)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cert cn='%s', expecting '%s'", buf, cn);
  /* don't match because of truncation - this will require a hostname > 512 characters, though */
  if(strlen(cn) >= sizeof(buf) - 1)
    return FALSE;

  /* patch submitted by Earl Fogel for MAS-5 */
  if(buf[0] == '*' && c->vsac_allow_wildcard_cert != FALSE) {
    do {
      domain = strchr(domain + (domain[0] == '.' ? 1 : 0), '.');
      if(domain != NULL && apr_strnatcasecmp(buf+1, domain) == 0)
        return TRUE;
    } while (domain != NULL);
  } else {
    if(apr_strnatcasecmp(buf, cn) == 0)
      return TRUE;
  }

  return FALSE;
}

static char *getResponseFromServer(request_rec *r, vsac_dir_cfg *dc,
                                   const char *user, const char *password)
{
  char *validateRequest, validateResponse[VSAC_MAX_RESPONSE_SIZE];
  apr_finfo_t f;
  char *payload;
  int i, bytesIn;
  socket_t s = INVALID_SOCKET;
  vsac_cfg *c = ap_get_module_config(r->server->module_config, &authn_vsac_module);

  SSL_METHOD *m;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  struct sockaddr_in sa;
  struct hostent *server;
  char *server_name;
  int server_port;
  int ret;

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Debug mode is %s", c->vsac_debug ? "On" : "Off");

  if(c->vsac_debug)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering getResponseFromServer()");
#ifdef WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0){
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: cannot initialize winsock2: (%d)", SWAGetLastError());
    return NULL;
  }
#endif

  if(c->vsac_use_proxy) {
    server_name = c->vsac_proxy_host;
    server_port = c->vsac_proxy_port;
  } else {
    server_name = c->vsac_uservalidate_url.hostname;
    server_port = c->vsac_uservalidate_url.port;
  }
  if(c->vsac_debug)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTHN_VSAC: use proxy: %s, will connect to %s:%d", c->vsac_use_proxy ? "Yes" : "No", server_name, server_port);

  server = gethostbyname(server_name);
  if(NULL == server) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: gethostbyname() failed for %s",
                  server_name);
    return NULL;
  }

  /* establish a TCP connection with the remote server */
  s = socket(AF_INET, SOCK_STREAM, 0);
  if(INVALID_SOCKET == s) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: socket() failed for %s", server_name);
    /* no need to close(s) here since it was never successfully created */
    VSACCleanupSocket(s, ssl, ctx);
    return NULL;
  }

  memset(&sa, 0, sizeof(struct sockaddr_in));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(server_port);
  memcpy(&(sa.sin_addr.s_addr), (server->h_addr_list[0]), sizeof(sa.sin_addr.s_addr));

  if(connect(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: connect() failed to %s:%d",
                  server_name, ntohs(sa.sin_port));
    VSACCleanupSocket(s, ssl, ctx);
    return NULL;
  }

  /* If using a proxy, issue a CONNECT to establish the SSL tunnel */
  if(c->vsac_use_proxy && isSSL(&(c->vsac_uservalidate_url))) {
    if(c->vsac_debug)
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Sending CONNECT %s:%d",
        c->vsac_uservalidate_url.hostname, c->vsac_uservalidate_url.port);
    validateRequest = apr_psprintf(r->pool, "CONNECT %s:%d\n\n",
        c->vsac_uservalidate_url.hostname, c->vsac_uservalidate_url.port);
    if(write(s, validateRequest, (int) strlen(validateRequest)) != strlen(validateRequest)) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: unable to send CONNECT to proxy %s",
                    c->vsac_proxy_host);
      VSACCleanupSocket(s, ssl, ctx);
      return NULL;
    }
    /* read proxy response */
    i = 0;
    do {
      bytesIn = read(s, validateResponse + i, (sizeof(validateResponse)-i-1));
      i += bytesIn;
      validateResponse[i] = '\0';
      if(c->vsac_debug)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Received %d bytes of repsonse '%s'", bytesIn, validateResponse);
    } while (bytesIn > 0 && (NULL == strstr(validateResponse, "\r\n\r\n")) && i < sizeof(validateResponse));

    if(c->vsac_debug)
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Proxy response: %s", validateResponse);
    if(strncasecmp(validateResponse, PROXY_CONNECT_RESPONSE, strlen(PROXY_CONNECT_RESPONSE))) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: unable to connect to %s",
      c->vsac_uservalidate_url.hostname);
      VSACCleanupSocket(s, ssl, ctx);
      return NULL;
    }
  }

  /* assign the created connection to an SSL object */
  SSL_library_init();
  m = SSLv23_method();
  ctx = SSL_CTX_new(m);

  if(c->vsac_validate_server != FALSE) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTHN_VSAC: using certificate path '%s'", c->vsac_certificate_path);

    if(apr_stat(&f, c->vsac_certificate_path, APR_FINFO_TYPE, r->pool) == APR_INCOMPLETE) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Could not load CA certificate: %s", c->vsac_certificate_path);
      VSACCleanupSocket(s, ssl, ctx);
      return NULL;
    }

    if(f.filetype == APR_DIR) {
ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Using CA directory");
      if(!(SSL_CTX_load_verify_locations(ctx, NULL, c->vsac_certificate_path))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Could not load CA certificate path: %s", c->vsac_certificate_path);
        VSACCleanupSocket(s, ssl, ctx);
        return NULL;
      }
    } else if (f.filetype == APR_REG) {
ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Using CA file");
      if(!(SSL_CTX_load_verify_locations(ctx, c->vsac_certificate_path, NULL))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Could not load CA certificate file: %s", c->vsac_certificate_path);
        VSACCleanupSocket(s, ssl, ctx);
        return NULL;
      }
    } else {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Could not process Certificate Authority: %s", c->vsac_certificate_path);
      VSACCleanupSocket(s, ssl, ctx);
      return NULL;
    }

    SSL_CTX_set_verify_depth(ctx, c->vsac_validate_depth);
  }

  ssl = SSL_new(ctx);

  if(NULL == ssl) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Could not create an SSL connection to %s",
                  c->vsac_uservalidate_url.hostname);
    VSACCleanupSocket(s, ssl, ctx);
    return NULL;
  }

  if(SSL_set_fd(ssl, s) == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Could not bind SSL connection to socket for %s",
                  c->vsac_uservalidate_url.hostname);
    VSACCleanupSocket(s, ssl, ctx);
    return NULL;
  }

  if((ret = SSL_connect(ssl)) <= 0) {
    unsigned long err;
    int i = 1;
    char buf[512];
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Could not perform SSL handshake with %s (check VSACCertificatePath), err code: %d",
                  c->vsac_uservalidate_url.hostname, SSL_get_error(ssl, ret));
    while((err = ERR_get_error()) != 0) {
      ERR_error_string(err, buf);
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "err[%d] - %s", i++, buf);
    }
    VSACCleanupSocket(s, ssl, ctx);
    return NULL;
  }

  /* validate the server certificate if we require it, first by verifying the CA
   * signature, then by verifying the CN of the certificate to the hostname */
  if(c->vsac_validate_server != FALSE) {
    /* SSL_get_verify_result() will return X509_V_OK if the server did not present a certificate, so we must make sure they do present one */
    if(SSL_get_verify_result(ssl) != X509_V_OK || SSL_get_peer_certificate(ssl) == NULL) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Certificate not presented or not signed by CA (from %s)", c->vsac_uservalidate_url.hostname);
      VSACCleanupSocket(s, ssl, ctx);
      return NULL;
    } else if(check_cert_cn(r, c, ctx, SSL_get_peer_certificate(ssl), c->vsac_uservalidate_url.hostname) == FALSE) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Certificate CN does not match %s", c->vsac_uservalidate_url.hostname);
      VSACCleanupSocket(s, ssl, ctx);
      return NULL;
    }
  }

  /* without Connection: close the HTTP/1.1 protocol defaults to tryig to keep
   * the connection alive.  This introduces ~15 second lag when receiving a
   * response.
   * MAS-14 reverts this to HTTP/1.0 because the code that retrieves the user
   * validation response can not handle transfer chunked encoding.  This will
   * be solved at a later date when migrating to libcurl/some other HTTP
   * library to perform user validation.  It also removes the
   * Connection: close header as the default behavior for HTTP/1.0 is
   * Connection: close
   */
  payload = apr_psprintf(r->pool, "licenseCode=%s&user=%s&password=%s",
    dc->vsac_license_code, user, password);
  if(c->vsac_use_proxy && !isSSL(&(c->vsac_uservalidate_url))) {
    validateRequest = apr_psprintf(r->pool,
      "POST %s HTTP/1.0\nHost: %s\nContent-type: application/x-www-form-urlencoded\n"
      "Content-length: %d\n\n%s",
      getVSACValidateURL(r, c, APR_URI_UNP_OMITUSERINFO), c->vsac_uservalidate_url.hostname,
      (int)strlen(payload), payload);
  } else {
    validateRequest = apr_psprintf(r->pool,
      "POST %s HTTP/1.0\nHost: %s\nContent-type:application/x-www-form-urlencoded\n"
      "Content-length: %d\n\n%s",
      getVSACValidateURL(r, c, APR_URI_UNP_OMITSITEPART), c->vsac_uservalidate_url.hostname,
      (int)strlen(payload), payload);
  }
  /* send our validation request */
  if(SSL_write(ssl, validateRequest, (int) strlen(validateRequest)) != strlen(validateRequest)) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: unable to write user vaidate request to %s",
    c->vsac_uservalidate_url.hostname);
    VSACCleanupSocket(s, ssl, ctx);
    return NULL;
  }

  /* read the response until there is no more */
  i = 0;
  do {
    bytesIn = SSL_read(ssl, validateResponse + i, (sizeof(validateResponse)-i-1));
    i += bytesIn;
    if(c->vsac_debug)
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Received %d bytes of repsonse", bytesIn);
  } while (bytesIn > 0 && i < sizeof(validateResponse));

  validateResponse[i] = '\0';

  if(c->vsac_debug)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Validation response: %s", validateResponse);

  if(bytesIn != 0 || i >= sizeof(validateResponse) - 1) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: oversized response received from %s",
                  c->vsac_uservalidate_url.hostname);
    VSACCleanupSocket(s, ssl, ctx);
    return NULL;
  }

  VSACCleanupSocket(s, ssl, ctx);

  return apr_pstrndup(r->pool, validateResponse, strlen(validateResponse));
}

static const command_rec authn_vsac_cmds[] =
{
  AP_INIT_TAKE1("VSACUserValidateURL", cfg_readVSACParameter,
                (void *)cmd_uservalidate_url,
                RSRC_CONF, "URL for validating if a user is a UMLS licensee"),
  AP_INIT_TAKE1("VSACDebug", cfg_readVSACParameter,
                (void *)cmd_debug,
                RSRC_CONF, "Enable or disable debug mode (On or Off)"),
  AP_INIT_TAKE1("VSACDistributorLicenseCode", ap_set_string_slot,
                (void *)APR_OFFSETOF(vsac_dir_cfg, vsac_license_code),
                OR_AUTHCFG, "Valid UMLS license code of the authorized content distributor"),
  AP_INIT_TAKE1("VSACUseProxy", cfg_readVSACParameter,
                (void *)cmd_use_proxy,
                RSRC_CONF, "is the VSAC service accessed through a proxy?"),
  AP_INIT_TAKE1("VSACProxyHost", cfg_readVSACParameter,
                (void *)cmd_proxy_host,
                RSRC_CONF, "hostname of the proxy server to use"),
  AP_INIT_TAKE1("VSACProxyPort", cfg_readVSACParameter,
                (void *)cmd_proxy_port,
                RSRC_CONF, "port on the proxy server to use"),

  /* ssl related options */
  AP_INIT_TAKE1("VSACValidateServer", cfg_readVSACParameter,
                (void *)cmd_validate_server,
                RSRC_CONF, "validate certificate of the server"),
  AP_INIT_TAKE1("VSACValidateDepth", cfg_readVSACParameter,
                (void *)cmd_validate_depth,
                RSRC_CONF, "Define the number of chained certificates required for a successful validation"),
  AP_INIT_TAKE1("VSACCertificatePath", cfg_readVSACParameter,
                (void *)cmd_ca_path,
                RSRC_CONF, "Path to the X509 certificate for the VSAC Server Certificate Authority"),
  AP_INIT_TAKE1("VSACAllowWildcardCert", cfg_readVSACParameter,
                (void *)cmd_wildcard_cert,
                RSRC_CONF, "Allow wildcards in certificates when performing validation (e.g. *.example.com) (On or Off)"),
  {NULL}
};

/**
 * This function uses the UMLS RESTful API to ensure that the user being
 * authenticated is a UMLS licensee.  If they are, they are granted access,
 * otherwise, they are denied.
 *
 * The UMLS authentication service is available at the following URL:
 * https://uts-ws.nlm.nih.gov/restful/IsValidUMLSUser
 * This service expects an HTTP POST call with three parameters:
 *   licenseCode -- Valid UMLS license code of the authorized content distributor
 *   user        -- UTS username of end-user
 *   password    -- UTS password of end-user
 *
 * If the credentials are valid, and the end-user is licensed, the API
 * responds with:
 * <Result>true</Result>
 *
 * If an incorrect username/password combo are sent, the API will respond with
 * a 400 Bad Request error.
 * If a valid username/password combo are sent, but the user is not a valid
 * licensee (license has expired), the API will return:
 * <Result>false</Result>
 *
 * @param[in] r The HTTP request object being processed.
 * @param[in] user The UTS username of the end-user.
 * @param[in] password The UTS password of the end-user.
 *
 * @return <em>AUTH_GENERAL_ERROR</em> If required config parameters were not
 *  defined; <em>AUTH_DENIED</em> If the users credentials are wrong, or they
 *  are not a current UTS licensee; <em>AUTH_GRANTED</em> if they should be
 *  allowed access.
 */
static authn_status check_password(request_rec *r, const char *user,
                                   const char *password)
{
  char *line;
  apr_xml_doc *doc;
  apr_xml_elem *node;
  apr_xml_parser *parser = apr_xml_parser_create(r->pool);
  vsac_cfg *c = (vsac_cfg *) ap_get_module_config(r->server->module_config,
                                                  &authn_vsac_module);
  vsac_dir_cfg *dc = 
    (vsac_dir_cfg *) ap_get_module_config(r->per_dir_config,
                                          &authn_vsac_module);
  const char *response = getResponseFromServer(r, dc, user, password);

  if(c->vsac_debug)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering check_password");

  if(NULL == response)
    return AUTH_DENIED;

  response = strstr((char *) response, "\r\n\r\n");

  if(NULL == response)
    return AUTH_DENIED;

  /* skip the \r\n\r\n after the HTTP headers */
  response += 4;

  /* parse the XML response */
  if(apr_xml_parser_feed(parser, response, strlen(response)) != APR_SUCCESS) {
    line = apr_pcalloc(r->pool, 512);
    apr_xml_parser_geterror(parser, line, 512);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: error parsing NLM response: %s", line);
    return AUTH_DENIED;
  }
  /* retrieve a DOM object */
  if(apr_xml_parser_done(parser, &doc) != APR_SUCCESS) {
    line = apr_pcalloc(r->pool, 512);
    apr_xml_parser_geterror(parser, line, 512);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: error retrieving XML document for NLM response: %s", line);
    return AUTH_DENIED;
  }
  /* XML tree:
   * <Result>true/false</Result>
   */
  node = doc->root;
  if(NULL != node && apr_strnatcmp(node->name, "Result") == 0) {
    line = (char *) (node->first_cdata.first->text);
    if(apr_strnatcasecmp(line, "true") == 0)
      return AUTH_GRANTED;
  } else
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Unexpected root node in response from NLM server: %s", node->name);

  return AUTH_DENIED;
}

static authn_status get_realm_hash(request_rec *r, const char *user,
                                   const char *realm, char **rethash)
{
  ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "get_realm_hash not implemented in mod_authn_vsac");
  return AUTH_USER_NOT_FOUND;
}

static int vsac_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s)
{
  vsac_cfg *c = ap_get_module_config(s->module_config, &authn_vsac_module);

  if(c->vsac_use_proxy) {
    /* make sure the proxy host and proxy port configuration options were provided */
    if(NULL == c->vsac_proxy_host) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
        "MOD_AUTHN_VSAC: VSACUseProxy is on, but VSACProxyHost not specified");
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    if(0 == c->vsac_proxy_port) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
        "MOD_AUTHN_VSAC: VSACUseProxy is on, but VSACProxyPort not specified");
      return HTTP_INTERNAL_SERVER_ERROR;
    } else if(c->vsac_proxy_port < 0) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
        "MOD_AUTHN_VSAC: VSAProxyPort invalid.  Must be > 0");
      return HTTP_INTERNAL_SERVER_ERROR;
    }
  }
  return OK;
}

static const authn_provider authn_vsac_provider =
{
  &check_password,
  &get_realm_hash,
};

static void register_hooks(apr_pool_t *p)
{
  ap_hook_post_config(vsac_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_register_provider(p, AUTHN_PROVIDER_GROUP, "vsac", "0",
                       &authn_vsac_provider);
}

module AP_MODULE_DECLARE_DATA authn_vsac_module =
{
  STANDARD20_MODULE_STUFF,
  vsac_create_dir_config,     /* dir config creater */
  vsac_merge_dir_config,      /* merge dir configs */
  vsac_create_server_config,  /* server config */
  vsac_merge_server_config,   /* merge server config */
  authn_vsac_cmds,            /* command apr_table_t */
  register_hooks              /* register hooks */
};
