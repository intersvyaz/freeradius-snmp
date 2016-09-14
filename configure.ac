AC_PREREQ([2.53])
AC_INIT(rlm_snmp.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_snmp])

if test x$with_[]modname != xno; then

    AC_PROG_CC

    smart_try_dir=
    FR_SMART_CHECK_LIB(netsnmp, init_snmp)
    if test "x$ac_cv_lib_netsnmp_init_snmp" != "xyes"; then
        fail="$fail libnetsnmp"
    fi

    smart_try_dir=
    FR_SMART_CHECK_INCLUDE([net-snmp/net-snmp-config.h])
    if test "$ac_cv_header_netmsnmp_netmsnmpmconfig_h" != "yes"; then
        fail="$fail net-snmp/net-snmp-config.h"
    fi

    targetname=modname

else
    targetname=
    echo \*\*\* module modname is disabled.
fi

if test x"$fail" != x""; then
    if test x"${enable_strict_dependencies}" = x"yes"; then
        AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
    else
        AC_MSG_WARN([silently not building ]modname[.])
        AC_MSG_ERROR([FAILURE: ]modname[ requires: $fail.]);
        targetname=""
    fi
fi

mod_ldflags=$SMART_LIBS
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)
