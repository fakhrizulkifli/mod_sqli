mod_sqli.la: mod_sqli.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_sqli.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_sqli.la
