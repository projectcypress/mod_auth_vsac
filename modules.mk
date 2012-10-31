mod_authn_vsac.la: mod_authn_vsac.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_vsac.lo $(LIBS)
DISTCLEAN_TARGETS = modules.mk
shared =  mod_authn_vsac.la
