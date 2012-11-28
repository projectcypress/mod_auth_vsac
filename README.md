This project is an Apache httpd module that performs authentication against the NLM VSAC license verification RESTful web service.  It was developed because the Cypress project had a need to restrict access to clinical codeset data to only individuals who had executed a license agreement with the NLM.

This document lists the various configuration options that the module supports and shows how to configure it in apache.

# Supported Directives

## Server level directives
The following directives are allowed to be used at the top level of httpd.conf or in a VirtualHost context:

* **VSACUserValidateURL** - This is the URL endpoint for the REST web service that is used to authenticate a user.  It defaults to the URL that was current at the time the module was developed: https://uts-ws.nlm.nih.gov/restful/IsValidUMLSUser
* **VSACDebug** - This is a flag that can be set to 'on' or 'off' to control whether or not this module should generate debug output.  If this is turned on, you should also ensure that the httpd _LogLevel_ directive is also set to **debug**.  **Default value: off**.
* **VSACUseProxy** - If this module needs to go through a proxy server in order to reach the VSAC web service specified by _VSACUserValidateURL_, then this directive should be set to 'on', and _VSACProxyHost_ and _VSACProxyPort_ should be set appropriately.  **Default value: off**.
* **VSACProxyHost** - This is the name of the proxy server that should be used to access the VSAC web service.  The value of this directive is ignored unless _VSACUseProxy_ is set.  There is no default value.
* **VSACProxyPort** - This is the port on the proxy server that should be used to access the VSAC web service.  The value of this directive is ignored unless _VSACUseProxy_ is set.  **Default value: 80**.
* **VSACValidateServer** - This directive can be set to 'on' or 'off'.  If it is on, then the server certificate of the VSAC web service host will be validated.  **Default value: on**.
* **VSACValidateDepth** - This directive controls the maximum number of chained certificates that will be checked for a successful server validation.  **Default value: 9**.
* **VSACCertificatePath** - This is the path that contains the trusted CA certificates that will be used when validating the VSAC web service servers certificate.  **Default value: /etc/ssl/certs/**.
* **VSACAllowWildcardCert** - This directive can be set to 'on' or 'off'.  If on, it allows server certificates that contain a wildcard name (e.g. \*.example.com).  **Default value: off**.
* **VSACCookiePath** - This directive specifies where the cookies that are assigned after a user successfully authenticates are written.  This directory must be writable by the user running the apache server.  **Default value: /dev/null**.
* **VSACCookieEntropy** - This directive controls the number of random bytes to use when generating a session cookie (larger values may result in slow cookie generation).  **Default value: 32**.
* **VSACCookieDomain** - This directive specifies the domain header for the mod_authn_vsac cookie.  **Default value: none**.
* **VSACCookieHttpOnly** - This directive can be set to 'on' or 'off'.  If it is on, then the 'HttpOnly' flag will be set on the mod_authn_vsac cookie (this may break RFC compliance).  **Default value: off**.
* **VSACTimeout** - This directive sets the maximum time (in seconds) that a session cookie is valid for, regardless of idle time. **Default value: 7200 (2 hours)**.
* **VSACIdleTimeout** - This directive sets the maximum time (in seconds) a session can be idle before reauthenticaiton is required.  **Default value: 3600 (1 hour)**.
* **VSACCacheCleanInterval** - This directive sets the amount of time (in seconds) between cache cleanups.  This value is checked when a new local ticket is issued or when a ticket expires.  **Default value: 1800 (30 minutes)**.

## Directory level directives

The following directives are allowed to be used in a directory context, or in a .htaccess file if applicable _AllowOverride_ directive contains the _AuthConfig_ grouping:

* **VSACDistributorLicenseCode** - The is the distributor license key that NLM provides once you exercise a distributor agreement with them.  There is no default value for this directive, but it **is required**.
* **VSACRenew** - This parameter controls whether the VSAC web service should be consulted on every request.  It can be set to 'on' or 'off'.  If set to on, then every access to the directory where this directive is used will result in the VSAC web service being contacted.  If it is off, then the first access will result in the VSAC web service being contacted and then a cookie will be set which will allow future requests to succeed for some amount of time (controlled by the _VSACTimeout_ directive.  **Default value: off**.
* **VSACCookie** - This parameter specifies the name of the cookie that this module will give the user after successful authentication for an HTTP session.  **Default value: MOD_AUTH_VSAC**.
* **VSACSecureCookie** - This parameter specifies the name of the cookie that this module will give the user after successful authentication for an HTTPS session.  **Default value: MOD_AUTH_VSAC_S**.

# Implementation Details

This module implements a Basic Authentication Provider with a name of **vsac**.  Once this module is loaded, it can be invoked to protect any resource by listing **vsac** in the value of an _AuthBasicProvider_ directive (and specifying the appropriate module specific directives).

If you just require that the user accessing a protected resource has a current UMLS license agreement in place, then include a **Require valid-user** directive as well.

# Example Configuration

Here is a sample configuration file that can be included into an httpd configuration (e.g. by creating a file in /etc/httpd/conf.d with the following contents).

This configuration will cause the users browser to prompt them for their NLM UMLS credentials whenever they access any resource under /protected/resource/.

```
LoadModule authn_vsac_module modules/mod_authn_vsac.so

VSACUserValidateURL https://uts-ws.nlm.nih.gov/restful/IsValidUMLSUser
VSACDebug on
VSACUseProxy On
VSACProxyHost my.proxy.server.com
VSACProxyPort 80
VSACValidateServer On
VSACAllowWildcardCert On
VSACCertificatePath /etc/ssl/certs
VSACCookiePath /var/cache/mod_auth_vsac/

<Location /protected/resource>
   AuthType basic
   AuthName "NLM VSAC Authorization"
   AuthBasicProvider vsac
   Require valid-user

   VSACDistributorLicenseCode my_private_license_code_here
</Location>
```
