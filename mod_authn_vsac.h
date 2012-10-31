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
#define VSAC_DEFAULT_USERVALIDATE_URL NULL
#define VSAC_DEFAULT_LICENSE_CODE NULL
#define VSAC_DEFAULT_USE_PROXY FALSE
#define VSAC_DEFAULT_PROXY_HOST NULL
#define VSAC_DEFAULT_PROXY_PORT 80
#define VSAC_DEFAULT_DEBUG FALSE
#define VSAC_DEFAULT_VALIDATE_SERVER TRUE
#define VSAC_DEFAULT_VALIDATE_DEPTH 9
#define VSAC_DEFAULT_CA_PATH "/etc/ssl/certs/"
#define VSAC_DEFAULT_ALLOW_WILDCARD_CERT 0

typedef struct vsac_cfg {
  int  vsac_use_proxy;
  int  vsac_proxy_port;
  char *vsac_proxy_host;
  char *vsac_certificate_path;
  unsigned int vsac_debug;
  unsigned int vsac_validate_server;
  unsigned int vsac_validate_depth;
  unsigned int vsac_allow_wildcard_cert;
  apr_uri_t vsac_uservalidate_url;
} vsac_cfg;

typedef struct vsac_dir_cfg {
  char *vsac_license_code;
} vsac_dir_cfg;

module AP_MODULE_DECLARE_DATA authn_vsac_module;

typedef enum { cmd_uservalidate_url, cmd_proxy_port, cmd_debug,
    cmd_validate_server, cmd_use_proxy, cmd_proxy_host, cmd_validate_depth,
    cmd_ca_path, cmd_wildcard_cert } valid_cmds;

#endif /* MOD_AUTHN_VSAC_H */
