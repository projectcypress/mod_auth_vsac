/*****************************************************************************
 * mod_authn_vsac
 *
 * Author: Tim Taylor <ttaylor@mitre.org>
 * Date: 26 Oct. 2012
 ****************************************************************************/

#ifndef MOD_AUTHN_VSAC_H
#define MOD_AUTHN_VSAC_H

#include "ap_release.h"

#ifndef AP_SERVER_MAJORVERSION_NUMBER
  #ifndef AP_SERVER_MINOR_VERSION_NUMBER
    #define APACHE2_0
  #endif
#endif

#ifndef APACHE2_0
  #ifdef AP_SERVER_MAJORVERSION_NUMBER
    #ifdef AP_SERVER_MINORVERSION_NUMBER
      #if ((AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER == 0))
        #define APACHE2_0
      #endif
    #endif
  #endif
#endif

#ifdef WIN32
typedef SOCKET socket_t;
#else
typedef int socket_t;
#define INVALID_SOCKET -1
#endif

#define VSAC_MAX_RESPONSE_SIZE 4096

#define PROXY_CONNECT_RESPONSE "HTTP/1.0 200 Connection established"

/* Default values for configuration settings */
#define VSAC_DEFAULT_USERVALIDATE_URL "https://uts-ws.nlm.nih.gov/restful/IsValidUMLSUser"
#define VSAC_DEFAULT_LICENSE_CODE NULL
#define VSAC_DEFAULT_USE_PROXY FALSE
#define VSAC_DEFAULT_PROXY_HOST NULL
#define VSAC_DEFAULT_PROXY_PORT 80
#define VSAC_DEFAULT_DEBUG FALSE
#define VSAC_DEFAULT_VALIDATE_SERVER TRUE
#define VSAC_DEFAULT_VALIDATE_DEPTH 9
#define VSAC_DEFAULT_CA_PATH "/etc/ssl/certs/"
#define VSAC_DEFAULT_ALLOW_WILDCARD_CERT 0
#define VSAC_DEFAULT_RENEW NULL
#define VSAC_DEFAULT_COOKIE_PATH "/dev/null"
#define VSAC_DEFAULT_COOKIE_ENTROPY 32
#define VSAC_DEFAULT_COOKIE_DOMAIN NULL
#define VSAC_DEFAULT_COOKIE_HTTPONLY 0
#define VSAC_DEFAULT_COOKIE_TIMEOUT 7200 /* 2 hours */
#define VSAC_DEFAULT_COOKIE_IDLE_TIMEOUT 3600 /* 1 hour */
#define VSAC_DEFAULT_CACHE_CLEAN_INTERVAL 1800 /* 30 minutes */
#define VSAC_DEFAULT_COOKIE "MOD_AUTH_VSAC"
#define VSAC_DEFAULT_SCOOKIE "MOD_AUTH_VSAC_S"

#define VSAC_MAX_ERROR_SIZE 1024
#define VSAC_MAX_XML_SIZE 1024

typedef struct vsac_cfg {
  int  vsac_use_proxy;
  int  vsac_proxy_port;
  char *vsac_proxy_host;
  char *vsac_certificate_path;
  char *vsac_cookie_path;
  char *vsac_cookie_domain;
  unsigned int vsac_debug;
  unsigned int vsac_validate_server;
  unsigned int vsac_validate_depth;
  unsigned int vsac_allow_wildcard_cert;
  unsigned int vsac_cache_clean_interval;
  unsigned int vsac_cookie_entropy;
  unsigned int vsac_timeout;
  unsigned int vsac_idle_timeout;
  unsigned int vsac_cookie_http_only;
  apr_uri_t vsac_uservalidate_url;
} vsac_cfg;

typedef struct vsac_dir_cfg {
  char *vsac_license_code;
  char *vsac_cookie;
  char *vsac_secure_cookie;
  char *vsac_renew;
} vsac_dir_cfg;

typedef struct vsac_cache_entry {
  char *user;
  apr_time_t issued;
  apr_time_t lastactive;
  char *path;
  apr_byte_t renewed;
  apr_byte_t secure;
  char *ticket;
} vsac_cache_entry;

module AP_MODULE_DECLARE_DATA authn_vsac_module;

typedef enum { cmd_uservalidate_url, cmd_proxy_port, cmd_debug,
    cmd_validate_server, cmd_use_proxy, cmd_proxy_host, cmd_validate_depth,
    cmd_ca_path, cmd_wildcard_cert, cmd_cookie_path, cmd_cookie_entropy,
    cmd_session_timeout, cmd_idle_timeout, cmd_cache_interval,
    cmd_cookie_domain, cmd_cookie_httponly} valid_cmds;

static apr_byte_t isValidVSACCookie(request_rec *r, vsac_cfg *c, char *cookie);
static apr_byte_t readVSACCacheFile(request_rec *r, vsac_cfg *c, char *name, vsac_cache_entry *cache);
static void deleteVSACCacheFile(request_rec *r, char *cookieName);
static void VSACCleanCache(request_rec *r, vsac_cfg *c);
static apr_byte_t writeVSACCacheEntry(request_rec *r, char *name, vsac_cache_entry *cache, apr_byte_t exists);
static char *createVSACCookie(request_rec *r, char *user, char *ticket);
static void setVSACCookie(request_rec *r, char *cookieName, char *cookieValue, apr_byte_t secure);
static char *url_encode(apr_pool_t *pool, const char *str);

#endif /* MOD_AUTHN_VSAC_H */
