/*****************************************************************************
 * mod_authn_vsac
 *
 * This apache module implements a Basic Authentication Provider that will
 * authenticate a user by invoking the NLM VSAC RESTful authentication.
 * service.  The need for this module is an unfortunate side-effect of NLM
 * deciding that they needed a REST API in front of a CAS server :(
 *
 * This module shamelessly borrows a lot of code from the mod_auth_cas module.
 * I want to thank the authors of that module: Phil Ames, and Matt Smith
 *
 * Author: Tim Taylor <ttaylor@mitre.org>
 * Date: 25 Oct. 2012
 *
 * Changes:
 * - 23 Jan 2015 - Removed the certificate trust check for each intermediate
 *      CA in the chain presented by the remote server.
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
#include "util_md5.h"
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
  char d;
  
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

    case cmd_cookie_path:
      /* probably redundant.  Same check in performed in vsac_post_config */
      if(apr_stat(&f, value, APR_FINFO_TYPE, cmd->temp_pool) == APR_INCOMPLETE)
        return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: Could not find VSACCookiePath '%s'", value));

      if(f.filetype != APR_DIR || value[strlen(value) - 1] != '/')
        return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: VSACCookiePath '%s' is not a directory or does not end in a trailing '/'!", value));
      c->vsac_cookie_path = apr_pstrdup(cmd->pool, value);
      break;
    case cmd_cookie_entropy:
      i = atoi(value);
      if(i > 0)
        c->vsac_cookie_entropy = i;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: Invalid VSACCookieEntropy (%s) specified - must be numeric", value));
      break;
    case cmd_session_timeout:
      i = atoi(value);
      if(i > 0)
        c->vsac_timeout = i;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: Invalid VSACTimeout (%s) specified - must be numeric", value));
      break;
    case cmd_idle_timeout:
      i = atoi(value);
      if(i > 0)
        c->vsac_idle_timeout = i;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: Invalid VSACIdleTimeout (%s) specified - must be numeric", value));
      break;

    case cmd_cache_interval:
      i = atoi(value);
      if(i > 0)
        c->vsac_cache_clean_interval = i;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: Invalid VSACCacheCleanInterval (%s) specified - must be numeric", value));
      break;
    case cmd_cookie_domain:
      for(i = 0; i < strlen(value); i++) {
        d = value[i];
        if( (d < '0' || d > '9') &&
            (d < 'a' || d > 'z') &&
            (d < 'A' || d > 'Z') &&
            d != '.' && d != '-') {
          return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: Invalid character (%c) in VSACCookieDomain", d));
        }
      }
      c->vsac_cookie_domain = apr_pstrdup(cmd->pool, value);
      break;
    case cmd_cookie_httponly:
      if(apr_strnatcasecmp(value, "On") == 0)
        c->vsac_cookie_http_only = TRUE;
      else if(apr_strnatcasecmp(value, "Off") == 0)
        c->vsac_cookie_http_only = FALSE;
      else
        return(apr_psprintf(cmd->pool, "MOD_AUTH_VSAC: Invalid argument to VSACCookieHttpOnly - must be 'On' or 'Off'"));
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
  c->vsac_cookie_path = VSAC_DEFAULT_COOKIE_PATH;
  c->vsac_cookie_entropy = VSAC_DEFAULT_COOKIE_ENTROPY;
  c->vsac_timeout = VSAC_DEFAULT_COOKIE_TIMEOUT;
  c->vsac_idle_timeout = VSAC_DEFAULT_COOKIE_IDLE_TIMEOUT;
  c->vsac_cache_clean_interval = VSAC_DEFAULT_CACHE_CLEAN_INTERVAL;
  c->vsac_cookie_domain = VSAC_DEFAULT_COOKIE_DOMAIN;
  c->vsac_cookie_http_only = VSAC_DEFAULT_COOKIE_HTTPONLY;

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
  c->vsac_cookie_path = ((strcmp(add->vsac_cookie_path, VSAC_DEFAULT_COOKIE_PATH) != 0) ? add->vsac_cookie_path : base->vsac_cookie_path);
  c->vsac_cookie_entropy = (add->vsac_cookie_entropy != VSAC_DEFAULT_COOKIE_ENTROPY ? add->vsac_cookie_entropy : base->vsac_cookie_entropy);
  c->vsac_timeout = (add->vsac_timeout != VSAC_DEFAULT_COOKIE_TIMEOUT ? add->vsac_timeout : base->vsac_timeout);
  c->vsac_idle_timeout = (add->vsac_idle_timeout != VSAC_DEFAULT_COOKIE_IDLE_TIMEOUT ? add->vsac_idle_timeout : base->vsac_idle_timeout);
  c->vsac_cache_clean_interval = (add->vsac_cache_clean_interval != VSAC_DEFAULT_CACHE_CLEAN_INTERVAL ? add->vsac_cache_clean_interval : base->vsac_cache_clean_interval);
  c->vsac_cookie_domain = (add->vsac_cookie_domain != VSAC_DEFAULT_COOKIE_DOMAIN ? add->vsac_cookie_domain : base->vsac_cookie_domain);
  c->vsac_cookie_http_only = (add->vsac_cookie_http_only != VSAC_DEFAULT_COOKIE_HTTPONLY ? add->vsac_cookie_http_only : base->vsac_cookie_http_only);

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
  c->vsac_cookie = VSAC_DEFAULT_COOKIE;
  c->vsac_secure_cookie = VSAC_DEFAULT_SCOOKIE;
  c->vsac_renew = VSAC_DEFAULT_RENEW;
  return c;
}

static void *vsac_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD)
{
	vsac_dir_cfg *c = apr_pcalloc(pool, sizeof(vsac_dir_cfg));
	vsac_dir_cfg *base = BASE;
	vsac_dir_cfg *add = ADD;

	/* inherit the previous directory's setting if applicable */
	c->vsac_license_code = (add->vsac_license_code != VSAC_DEFAULT_LICENSE_CODE ? add->vsac_license_code : base->vsac_license_code);
  c->vsac_cookie = ((strcmp(add->vsac_cookie, VSAC_DEFAULT_COOKIE) != 0) ? add->vsac_cookie : base->vsac_cookie);
  c->vsac_secure_cookie = ((strcmp(add->vsac_secure_cookie, VSAC_DEFAULT_SCOOKIE) != 0) ? add->vsac_cookie : base->vsac_cookie);
  c->vsac_renew = (add->vsac_renew != VSAC_DEFAULT_RENEW ? add->vsac_renew : base->vsac_renew);
  if(add->vsac_renew != NULL && strcasecmp(add->vsac_renew, "Off") == 0)
    c->vsac_renew = NULL;

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
  /* if(X509_verify_cert(xctx) == 0)
   *   return FALSE;
   */

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

static char *getVSACCookie(request_rec *r, const char *cookieName) {
  char *cookie, *tokenizerCtx, *rv = NULL;
  apr_byte_t cookieFound = FALSE;
  char *cookies = apr_pstrdup(r->pool,
                              (char *)apr_table_get(r->headers_in, "Cookie"));

  if(cookies != NULL) {
    /* tokenize on ; to find the cookie we want */
    cookie = apr_strtok(cookies, ";", &tokenizerCtx);
    do {
      while(cookie != NULL && *cookie == ' ')
        cookie++;
      if(strncmp(cookie, cookieName, strlen(cookieName)) == 0) {
        cookieFound = TRUE;
        /* skip to the value of the cookie (after the '=') */
        cookie += (strlen(cookieName) + 1);
        rv = apr_pstrdup(r->pool, cookie);
      }
      cookie = apr_strtok(NULL, ";", &tokenizerCtx);
      /* no more cookies */
      if(cookie == NULL)
        break;
    } while (cookieFound == FALSE);
  }

  return rv;
}

static const char *getResponseFromServer(request_rec *r, const char *user,
                      const char *password)
{
  char *validateRequest, validateResponse[VSAC_MAX_RESPONSE_SIZE];
  apr_finfo_t f;
  char *payload;
  char *encoded_license = NULL, *encoded_user = NULL, *encoded_passwd = NULL;
  int i, bytesIn;
  socket_t s = INVALID_SOCKET;
  vsac_cfg *c = ap_get_module_config(r->server->module_config, &authn_vsac_module);
  vsac_dir_cfg *dc = ap_get_module_config(r->per_dir_config, &authn_vsac_module);

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
  encoded_license = url_encode(r->pool, dc->vsac_license_code);
  encoded_user    = url_encode(r->pool, user);
  encoded_passwd  = url_encode(r->pool, password);
  payload = apr_psprintf(r->pool, "licenseCode=%s&user=%s&password=%s",
    encoded_license, encoded_user, encoded_passwd);
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
  AP_INIT_TAKE1("VSACRenew", ap_set_string_slot,
                (void *)APR_OFFSETOF(vsac_dir_cfg, vsac_renew),
                ACCESS_CONF|OR_AUTHCFG, "Force credential renew (/app/secure/ will require renew on /app/secure/*)"),

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

  /* cache options */
  AP_INIT_TAKE1("VSACCookiePath", cfg_readVSACParameter,
                (void *)cmd_cookie_path,
                RSRC_CONF, "Path to store the VSAC session cookies in (must end in trailing /)"),
  AP_INIT_TAKE1("VSACCookieEntropy", cfg_readVSACParameter,
                (void *)cmd_cookie_entropy,
                RSRC_CONF, "Number of random bytes to use when generating a session cookie (larger values may result in slow cookie generation)"),
  AP_INIT_TAKE1("VSACCookieDomain", cfg_readVSACParameter,
                (void *)cmd_cookie_domain,
                RSRC_CONF, "Specify domain header for mod_auth_vsac cookie"),
  AP_INIT_TAKE1("VSACCookieHttpOnly", cfg_readVSACParameter,
                (void *)cmd_cookie_httponly,
                RSRC_CONF, "Enable 'HttpOnly' flag for mod_auth_vsac cookie (may break RFC compliance)"),
  AP_INIT_TAKE1("VSACCookie", ap_set_string_slot,
                (void *) APR_OFFSETOF(vsac_dir_cfg, vsac_cookie),
                ACCESS_CONF|OR_AUTHCFG, "Define the cookie name for HTTP sessions"),
	AP_INIT_TAKE1("VSACSecureCookie", ap_set_string_slot,
                (void *) APR_OFFSETOF(vsac_dir_cfg, vsac_secure_cookie),
                ACCESS_CONF|OR_AUTHCFG, "Define the cookie name for HTTPS sessions"),

	/* cache timeout options */
	AP_INIT_TAKE1("VSACTimeout", cfg_readVSACParameter,
                (void *)cmd_session_timeout,
                RSRC_CONF, "Maximum time (in seconds) a session cookie is valid for, regardless of idle time"),
	AP_INIT_TAKE1("VSACIdleTimeout", cfg_readVSACParameter,
                (void *)cmd_idle_timeout,
                RSRC_CONF, "Maximum time (in seconds) a session can be idle for"),
	AP_INIT_TAKE1("VSACCacheCleanInterval", cfg_readVSACParameter,
                (void *)cmd_cache_interval,
                RSRC_CONF, "Amount of time (in seconds) between cache cleanups.  This value is checked when a new local ticket is issued or when a ticket expires."),
  {NULL}
};

/* r->parsed_uri.path will return something like /xyz/index.html - this removes the file portion */
static char *getVSACPath(request_rec *r)
{
	char *p = r->parsed_uri.path, *rv;
	size_t i, l = 0;
	for(i = 0; i < strlen(p); i++) {
		if(p[i] == '/')
			l = i;
	}
  rv = apr_pstrndup(r->pool, p, (l+1));
	return(rv);
}

static apr_byte_t isValidVSACCookie(request_rec *r, vsac_cfg *c, char *cookie)
{
	vsac_cache_entry cache;
#ifdef HAVE_RENEW
	vsac_dir_cfg *dc = ap_get_module_config(r->per_dir_config, &authn_vsac_module);
#endif

	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering isValidVSACCookie()");

	/* corrupt or invalid file */
	if(readVSACCacheFile(r, c, cookie, &cache) != TRUE) {
		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' is corrupt or invalid", cookie);
		return FALSE;
	}

	/* 
	 * mitigate session hijacking by not allowing cookies transmitted in the clear to be submitted
	 * for HTTPS URLs and by voiding HTTPS cookies sent in the clear
	 */
	if(   (isRequestSSL(r) == TRUE && cache.secure == FALSE)
     || (isRequestSSL(r) == FALSE && cache.secure == TRUE) ) {
		/* delete this file since it is no longer valid */
		deleteVSACCacheFile(r, cookie);
		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' not transmitted via proper HTTP(S) channel, expiring", cookie);
		VSACCleanCache(r, c);
		return FALSE;
	}

	if(   cache.issued < (apr_time_now()-(c->vsac_timeout*((apr_time_t) APR_USEC_PER_SEC)))
     || cache.lastactive < (apr_time_now()-(c->vsac_idle_timeout*((apr_time_t) APR_USEC_PER_SEC)))) {
		/* delete this file since it is no longer valid */
		deleteVSACCacheFile(r, cookie);
		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' is expired, deleting", cookie);
		VSACCleanCache(r, c);
		return FALSE;
	}

	/* see if this cookie contained 'renewed' credentials if this directory requires it */
#ifdef HAVE_RENEW
	if(cache.renewed == FALSE && dc->vsac_renew != NULL) {
		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' does not contain renewed credentials", cookie);
		return FALSE;
	} else if(d->vsac_renew != NULL && cache.renewed == TRUE) {
		/* make sure the paths match */
		if(strncasecmp(cache.path, getVSACScope(r), strlen(getVSACScope(r))) != 0) {
			if(c->vsac_debug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' does not contain renewed credentials for scope '%s' (path '%s')", cookie, getVSACScope(r), getVSACPath(r));
			return FALSE;
		}
	}
#endif /* HAVE_RENEW */

	cache.lastactive = apr_time_now();
	if(writeVSACCacheEntry(r, cookie, &cache, TRUE) == FALSE && c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Could not update cache entry for '%s'", cookie);

	return TRUE;
}

static char *createVSACCookie(request_rec *r, char *user, char *ticket)
{
	char *path, *buf, *rv;
	apr_file_t *f;
	apr_byte_t createSuccess;
	vsac_cache_entry e;
	int i;
	vsac_cfg *c = ap_get_module_config(r->server->module_config, &authn_vsac_module);
	vsac_dir_cfg *dc = ap_get_module_config(r->per_dir_config, &authn_vsac_module);
	buf = apr_pcalloc(r->pool, c->vsac_cookie_entropy);

	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering createVSACCookie()");

	VSACCleanCache(r, c);

	e.user = user;
	e.issued = apr_time_now();
	e.lastactive = apr_time_now();
	e.path = getVSACPath(r);
	e.renewed = (dc->vsac_renew == NULL ? 0 : 1);
	e.secure = (isRequestSSL(r) == TRUE ? 1 : 0);
	e.ticket = ticket;

	do {
		createSuccess = FALSE;
		/* this may block since this reads from /dev/random - however, it hasn't been a problem in testing */
		apr_generate_random_bytes((unsigned char *) buf, c->vsac_cookie_entropy);
		rv = (char *) ap_md5_binary(r->pool, (unsigned char *) buf, c->vsac_cookie_entropy);

		/* 
		 * Associate this text with user for lookups later.  By using files instead of 
		 * shared memory the advantage of NFS shares in a clustered environment or a 
		 * memory based file systems can be used at the expense of potentially some performance
		 */
		createSuccess = writeVSACCacheEntry(r, rv, &e, FALSE);

		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' created for user '%s'", rv, user);
	} while (createSuccess == FALSE);

	buf = (char *) ap_md5_binary(r->pool, (const unsigned char *) ticket, (int) strlen(ticket));
	path = apr_psprintf(r->pool, "%s.%s", c->vsac_cookie_path, buf);

	if((i = apr_file_open(&f, path, APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_EXCL, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Service Ticket to Cookie map file '%s' could not be created: %s", path, apr_strerror(i, buf, strlen(buf)));
		return FALSE;
	} else {
		apr_file_printf(f, "%s", rv);
		apr_file_close(f);
	}
	
	return(apr_pstrdup(r->pool, rv));
}

static void setVSACCookie(request_rec *r, char *cookieName, char *cookieValue, apr_byte_t secure)
{
	char *headerString, *currentCookies;
	vsac_cfg *c = ap_get_module_config(r->server->module_config, &authn_vsac_module);

	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering setVSACCookie()");

	headerString = apr_psprintf(r->pool, "%s=%s%s%s%s%s", cookieName, cookieValue, (secure ? ";Secure" : ""), (c->vsac_cookie_domain != NULL ? ";Domain=" : ""), (c->vsac_cookie_domain != NULL ? c->vsac_cookie_domain : ""), (c->vsac_cookie_http_only != FALSE ? "; HttpOnly" : ""));

	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only prints on 2xx responses */
	apr_table_add(r->err_headers_out, "Set-Cookie", headerString);

	/*
	 * There is a potential problem here.  If VSACRenew is on and a user requests 'http://example.com/xyz/'
	 * then they are bounced out to the NLM server and they come back with a ticket.  This ticket is validated
	 * and then this function (setVSACCookie) is installed.  However, mod_dir will create a subrequest to
	 * point them to some DirectoryIndex value.  mod_auth_vsac will see this new request (with no ticket since
	 * we removed it, but it would be invalid anyway since it was already validated at the NLM server)
	 * and redirect the user back to the NLM server (this time appending 'index.html' or something similar
	 * to the request) requiring two logins.  By adding this cookie to the incoming headers, when the
	 * subrequest is sent, they will use their established session.
	 */
	if((currentCookies = (char *) apr_table_get(r->headers_in, "Cookie")) == NULL)
		apr_table_add(r->headers_in, "Cookie", headerString);
	else
		apr_table_set(r->headers_in, "Cookie", (apr_pstrcat(r->pool, headerString, ";", currentCookies, NULL)));
	
	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Adding outgoing header: Set-Cookie: %s", headerString);

	return;
}

static apr_byte_t readVSACCacheFile(request_rec *r, vsac_cfg *c, char *name,
                                    vsac_cache_entry *cache)
{
	apr_off_t begin = 0;
	apr_file_t *f;
	apr_finfo_t fi;
	apr_xml_parser *parser;
	apr_xml_doc *doc = NULL;
	apr_xml_elem *e = NULL;
	char errbuf[VSAC_MAX_ERROR_SIZE];
	char *path, *val;
	int i;

	if(c->vsac_debug) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering readVSACCacheFile()");
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "using cookie: '%s'", name);
	}

	/* first, validate that cookie looks like an MD5 string */
	if(strlen(name) != APR_MD5_DIGESTSIZE*2) {
		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Invalid cache cookie length for '%s', (expecting %d, got %d)", name, APR_MD5_DIGESTSIZE*2, (int) strlen(name));
		return FALSE;
	}

	for(i = 0; i < APR_MD5_DIGESTSIZE*2; i++) {
		if((name[i] < 'a' || name[i] > 'f') && (name[i] < '0' || name[i] > '9')) {
			if(c->vsac_debug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Invalid character in cache cookie '%s' (%c)", name, name[i]);
			return FALSE;
		}
	}

	/* fix MAS-4 JIRA issue */
	if(apr_stat(&fi, c->vsac_cookie_path, APR_FINFO_TYPE, r->pool) == APR_INCOMPLETE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Could not find Cookie Path '%s'", c->vsac_cookie_path);
		return FALSE;
	}

	if(fi.filetype != APR_DIR || c->vsac_cookie_path[strlen(c->vsac_cookie_path)-1] != '/') {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Cookie Path '%s' is not a directory or does not end in a trailing '/'!", c->vsac_cookie_path);
		return FALSE;
	}
	/* end MAS-4 JIRA issue */

	/* open the file if it exists and make sure that the ticket has not expired */
	path = apr_psprintf(r->pool, "%s%s", c->vsac_cookie_path, name);

	/* Check that the file isn't 0 length */
	if(apr_stat(&fi, path, APR_FINFO_SIZE, r->pool) == APR_INCOMPLETE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Could not get size of cookie file '%s'", path);
		return FALSE;
	}
	if(fi.size == 0) {
		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_VSAC: Cookie file '%s' has 0 length -- invalid.", path);
		return FALSE;
	}

	if(apr_file_open(&f, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		if(c->vsac_debug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache entry '%s' could not be opened", name);
		return FALSE;
	}

	apr_file_lock(f, APR_FLOCK_SHARED);

	/* read the various values we store */
	apr_file_seek(f, APR_SET, &begin);

	if(apr_xml_parse_file(r->pool, &parser, &doc, f, VSAC_MAX_XML_SIZE) != APR_SUCCESS) {
		apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Error parsing XML content for '%s' (%s)", name, errbuf);
		return FALSE;
	}

	if(doc)
		e = doc->root->first_child;
	/* XML structure: 
 	 * cacheEntry
	 *	attr
	 *	attr
	 *	...
 	 */

	/* initialize things to sane values */
	cache->user = NULL;
	cache->issued = 0;
	cache->lastactive = 0;
	cache->path = "";
	cache->renewed = FALSE;
	cache->secure = FALSE;
	cache->ticket = NULL;

	do {
		if(e == NULL)
			continue;

		/* first_cdata.first is NULL on empty attributes (<attr />) */
		if(e->first_cdata.first != NULL)
			val = (char *)  e->first_cdata.first->text;
		else
			val = NULL;

		if (apr_strnatcasecmp(e->name, "user") == 0)
			cache->user = apr_pstrndup(r->pool, val, strlen(val));
		else if (apr_strnatcasecmp(e->name, "issued") == 0) {
			if(sscanf(val, "%" APR_TIME_T_FMT, &(cache->issued)) != 1)
				return FALSE;
		} else if (apr_strnatcasecmp(e->name, "lastactive") == 0) {
			if(sscanf(val, "%" APR_TIME_T_FMT, &(cache->lastactive)) != 1)
				return FALSE;
		} else if (apr_strnatcasecmp(e->name, "path") == 0)
			cache->path = apr_pstrndup(r->pool, val, strlen(val));
		else if (apr_strnatcasecmp(e->name, "renewed") == 0)
			cache->renewed = TRUE;
		else if (apr_strnatcasecmp(e->name, "secure") == 0)
			cache->secure = TRUE;
		else if (apr_strnatcasecmp(e->name, "ticket") == 0)
			cache->ticket = apr_pstrndup(r->pool, val, strlen(val));
		else
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Unknown cookie attribute '%s'", e->name);
		e = e->next;
	} while (e != NULL);

	apr_file_unlock(f);
	apr_file_close(f);
	return TRUE;
}

static void deleteVSACCacheFile(request_rec *r, char *cookieName)
{
	char *path, *ticket;
	vsac_cache_entry e;
	vsac_cfg *c = ap_get_module_config(r->server->module_config, &authn_vsac_module);

	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering deleteVSACCacheFile()");

	/* we need this to get the ticket */
	readVSACCacheFile(r, c, cookieName, &e);

	/* delete their cache entry */
	path = apr_psprintf(r->pool, "%s%s", c->vsac_cookie_path, cookieName);
	apr_file_remove(path, r->pool);

	/* delete the ticket -> cache entry mapping */
	ticket = (char *) ap_md5_binary(r->pool, (unsigned char *) e.ticket, strlen(e.ticket));
	path = apr_psprintf(r->pool, "%s.%s", c->vsac_cookie_path, ticket);
	apr_file_remove(path, r->pool);

	return;
}

static void VSACCleanCache(request_rec *r, vsac_cfg *c)
{
	apr_time_t lastClean;
	apr_off_t begin = 0;
	char *path;
	apr_file_t *metaFile, *cacheFile;
	char line[64];
	apr_status_t i;
	vsac_cache_entry cache;
	apr_dir_t *cacheDir;
	apr_finfo_t fi;

	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering VSACCleanCache()");

	path = apr_psprintf(r->pool, "%s.metadata", c->vsac_cookie_path);


	if(apr_file_open(&metaFile, path, APR_FOPEN_READ|APR_FOPEN_WRITE, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool) != APR_SUCCESS) {
		/* file does not exist or cannot be opened - try and create it */
		if((i = apr_file_open(&metaFile, path, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), (APR_FPROT_UREAD|APR_FPROT_UWRITE), r->pool)) != APR_SUCCESS) {
			apr_strerror(i, line, sizeof(line));
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MOD_AUTH_VSAC: Could not create cache metadata file '%s': %s", path, line);
			return;
		}
	}

	apr_file_lock(metaFile, APR_FLOCK_EXCLUSIVE);
	apr_file_seek(metaFile, APR_SET, &begin);

	/* if the file was not created on this method invocation (APR_FOPEN_READ is not used above during creation) see if it is time to clean the cache */
	if((apr_file_flags_get(metaFile) & APR_FOPEN_READ) != 0) {
		apr_file_gets(line, sizeof(line), metaFile);
		if(sscanf(line, "%" APR_TIME_T_FMT, &lastClean) != 1) { /* corrupt file */
			apr_file_close(metaFile);
			apr_file_remove(path, r->pool);
			if(c->vsac_debug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache metadata file is corrupt");
			return;
		}
		if(lastClean > (apr_time_now()-(c->vsac_cache_clean_interval*((apr_time_t) APR_USEC_PER_SEC)))) { /* not enough time has elapsed */
			if(c->vsac_debug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Insufficient time elapsed since last cache clean");
			return;
		}

		apr_file_seek(metaFile, APR_SET, &begin);
		apr_file_trunc(metaFile, begin);
	}

	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Beginning cache clean");

	apr_file_printf(metaFile, "%" APR_TIME_T_FMT "\n", apr_time_now());
	apr_file_unlock(metaFile);
	apr_file_close(metaFile);

	/* read all the files in the directory */
	if(apr_dir_open(&cacheDir, c->vsac_cookie_path, r->pool) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MOD_AUTH_VSAC: Error opening cache directory '%s' for cleaning", c->vsac_cookie_path);
	}

	do {
		i = apr_dir_read(&fi, APR_FINFO_NAME, cacheDir);
		if(i == APR_SUCCESS) {
			if(fi.name[0] == '.') /* skip hidden files and parent directories */
				continue;
			path = apr_psprintf(r->pool, "%s%s", c->vsac_cookie_path, fi.name);
			if(c->vsac_debug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Processing cache file '%s'", fi.name);

			if(apr_file_open(&cacheFile, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Unable to clean cache entry '%s'", path);
				continue;
			}
			if(readVSACCacheFile(r, c, (char *) fi.name, &cache) == TRUE) {
				if(cache.issued < (apr_time_now()-(c->vsac_timeout*((apr_time_t) APR_USEC_PER_SEC)))
           || cache.lastactive < (apr_time_now()-(c->vsac_idle_timeout*((apr_time_t) APR_USEC_PER_SEC)))) {
					/* delete this file since it is no longer valid */
					apr_file_close(cacheFile);
					deleteVSACCacheFile(r, (char *) fi.name);
					if(c->vsac_debug)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Removing expired cache entry '%s'", fi.name);
				}
			} else {
				if(c->vsac_debug)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Removing corrupt cache entry '%s'", fi.name);
				/* corrupt file */
				apr_file_close(cacheFile);
				deleteVSACCacheFile(r, (char *) fi.name);
			}
		}
	} while (i == APR_SUCCESS);
	apr_dir_close(cacheDir);
}

static apr_byte_t writeVSACCacheEntry(request_rec *r, char *name, vsac_cache_entry *cache, apr_byte_t exists)
{
	char *path;
	apr_file_t *f;
	apr_off_t begin = 0;
	int i;
	apr_byte_t lock = FALSE;
	vsac_cfg *c = ap_get_module_config(r->server->module_config, &authn_vsac_module);

	if(c->vsac_debug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering writeVSACCacheEntry()");

	path = apr_psprintf(r->pool, "%s%s", c->vsac_cookie_path, name);

	if(exists == FALSE) {
		if((i = apr_file_open(&f, path, APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_EXCL, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Cookie file '%s' could not be created: %s", path, apr_strerror(i, name, strlen(name)));
			return FALSE;
		}
	} else {
		if((i = apr_file_open(&f, path, APR_FOPEN_READ|APR_FOPEN_WRITE, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: Cookie file '%s' could not be opened: %s", path, apr_strerror(i, name, strlen(name)));
			return FALSE;
		}

		/* update the file with a new idle time if a write lock can be obtained */
		if(apr_file_lock(f, APR_FLOCK_EXCLUSIVE) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_VSAC: could not obtain an exclusive lock on %s", path);
			apr_file_close(f);
			return FALSE;
		} else
			lock = TRUE;
		apr_file_seek(f, APR_SET, &begin);
		apr_file_trunc(f, begin);
	}

	/* this is ultra-ghetto, but the APR really doesn't provide any facilities for easy DOM-style XML creation. */
	apr_file_printf(f, "<cacheEntry xmlns=\"http://uconn.edu/cas/mod_auth_cas\">\n");
	apr_file_printf(f, "<user>%s</user>\n", apr_xml_quote_string(r->pool, cache->user, TRUE));
	apr_file_printf(f, "<issued>%" APR_TIME_T_FMT "</issued>\n", cache->issued);
	apr_file_printf(f, "<lastactive>%" APR_TIME_T_FMT "</lastactive>\n", cache->lastactive);
	apr_file_printf(f, "<path>%s</path>\n", apr_xml_quote_string(r->pool, cache->path, TRUE));
	apr_file_printf(f, "<ticket>%s</ticket>\n", apr_xml_quote_string(r->pool, cache->ticket, TRUE));
	if(cache->renewed != FALSE)
		apr_file_printf(f, "<renewed />\n");
	if(cache->secure != FALSE)
		apr_file_printf(f, "<secure />\n");
	apr_file_printf(f, "</cacheEntry>\n");

	if(lock != FALSE)
		apr_file_unlock(f);

	apr_file_close(f);

	return TRUE;
}

static apr_byte_t isValidUser(request_rec *r, const char *user,
                      const char *password)
{
  char *line;
  apr_xml_parser *parser = apr_xml_parser_create(r->pool);
  apr_xml_doc *doc;
  apr_xml_elem *node;
  const char *response = NULL;

  response = getResponseFromServer(r, user, password);

  if(NULL == response)
    return FALSE;

  response = strstr((char *) response, "\r\n\r\n");

  if(NULL == response)
    return FALSE;

  /* skip the \r\n\r\n after the HTTP headers */
  response += 4;

  /* parse the XML response */
  if(apr_xml_parser_feed(parser, response, strlen(response)) != APR_SUCCESS) {
    line = apr_pcalloc(r->pool, 512);
    apr_xml_parser_geterror(parser, line, 512);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: error parsing NLM response: %s", line);
    return FALSE;
  }
  /* retrieve a DOM object */
  if(apr_xml_parser_done(parser, &doc) != APR_SUCCESS) {
    line = apr_pcalloc(r->pool, 512);
    apr_xml_parser_geterror(parser, line, 512);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: error retrieving XML document for NLM response: %s", line);
    return FALSE;
  }
  /* XML tree:
   * <Result>true/false</Result>
   */
  node = doc->root;
  if(NULL != node && apr_strnatcmp(node->name, "Result") == 0) {
    line = (char *) (node->first_cdata.first->text);
    if(apr_strnatcasecmp(line, "true") == 0)
      return TRUE;
  } else
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTHN_VSAC: Unexpected root node in response from NLM server: %s", node->name);

  return FALSE;
}

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
  vsac_cfg *c = (vsac_cfg *) ap_get_module_config(r->server->module_config,
                                                  &authn_vsac_module);
  vsac_dir_cfg *dc = 
    (vsac_dir_cfg *) ap_get_module_config(r->per_dir_config,
                                          &authn_vsac_module);
  char *cookieString = NULL;
  char *t = NULL;
  char *ticket = NULL;
  apr_byte_t ssl;
  
  if(c->vsac_debug)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering check_password");
  ssl = isRequestSSL(r);

  /* the presence of our cookie means we don't need to talk to NLM service */
  cookieString = getVSACCookie(r, (ssl ? dc->vsac_secure_cookie : dc->vsac_cookie));
  if(cookieString && isValidVSACCookie(r, c, cookieString))
    return AUTH_GRANTED;

  /* Either the cookie expired, or they don't have one */
  if(isValidUser(r, user, password)) {
    t = apr_psprintf(r->pool, "%" APR_TIME_T_FMT "%s%s", apr_time_now(), dc->vsac_license_code, user);
    ticket = apr_psprintf(r->pool, "ST-%s", (char *)ap_md5(r->pool, (unsigned char *)t));
    if(c->vsac_debug)
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Created ticket '%s' for user '%s'", ticket, user);
    cookieString = createVSACCookie(r, user, ticket);
    setVSACCookie(r,
      (ssl ? dc->vsac_secure_cookie : dc->vsac_cookie), cookieString, ssl);
    return AUTH_GRANTED;
  }

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
  apr_finfo_t f;

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

  if(apr_stat(&f, c->vsac_cookie_path, APR_FINFO_TYPE, pool) == APR_INCOMPLETE) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "MOD_AUTH_VSAC: Could not find VSACCookiePath '%s'", c->vsac_cookie_path);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  if(f.filetype != APR_DIR || c->vsac_cookie_path[strlen(c->vsac_cookie_path) - 1] != '/') {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "MOD_AUTH_VSAC: VSACCookiePath '%s' is not a directory or does not end in a trailing '/'!", c->vsac_cookie_path);
    return HTTP_INTERNAL_SERVER_ERROR;
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

/**
 * This function converts the given input string to an URL encoded string and
 * returns that as a new allocated string. All input characters that are not
 * a-z, A-Z, 0-9, '-', '.', '_' or '~' are converted to their "URL escaped"
 * version (%NN where NN is a two-digit hexadecimal number).
 */
static char *url_encode(apr_pool_t *pool, const char *str) {
  static char hex[] = "0123456789abcdef";
  const char *pstr = str;
  char *buf = (char *)apr_palloc(pool, strlen(str) * 3 + 1); /* maximum size if every char escaped */
  char *pbuf = buf;
  while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
      *pbuf++ = *pstr;
    else if (*pstr == ' ')
      *pbuf++ = '+';
    else {
      *pbuf++ = '%';
      *pbuf++ = hex[(*pstr >>4) & 0xf];
      *pbuf++ = hex[*pstr & 0xf];
    }
    pstr++;
  }
  *pbuf = '\0';
  return buf;
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
