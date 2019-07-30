%define name pivauth
%define version 1.0.3
%define release 1

Packager: Ben Allen
Summary: Tools for interoperability between AD/LDAP managed PIV credentials and OpenSSH
Name: %{name}
Version: %{version}
Release: %{release}
BuildArch: x86_64
Source0: %{name}-%{version}.tar.gz
License: BSD
Group: Applications/System
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release} -n)
Vendor: Argonne National Laboratory

Requires(pre): shadow-utils
Requires: /usr/bin/ldapsearch
Requires: /usr/bin/openssl

%description
Tools for interoperability between AD/LDAP managed PIV credentials and OpenSSH

%prep
%setup -q

%build
GCC=`which gcc 2>/dev/null`

if [ "X$GCC" != "X" ];then
    $GCC -o pubkey2ssh pubkey2ssh.c -L/usr/lib64 -lcrypto

    if [ "$?" != "0" ];then
        exit 1
    fi
fi
bash -x ./pivauth_test.sh

%install
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/sysconfig
mkdir -p ${RPM_BUILD_ROOT}/%{_bindir}
mkdir -p ${RPM_BUILD_ROOT}/%{_sbindir}
mkdir -p ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/examples/
mkdir -p ${RPM_BUILD_ROOT}/%{_localstatedir}/cache/pivauth

cp Docs/Examples/pivauth.crl_example.sysconfig ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/examples/pivauth.crl_example.sysconfig
cp Docs/Examples/pivauth.ocsp_example.sysconfig ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/examples/pivauth.ocsp_example.sysconfig
cp Docs/Examples/pivauth_ocsp_example.sh ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/examples/pivauth_ocsp_example.sh
cp LICENSE ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/LICENSE

cp pivauth.sh ${RPM_BUILD_ROOT}/%{_sbindir}/pivauth
cp pubkey2ssh ${RPM_BUILD_ROOT}/%{_bindir}/pubkey2ssh
cp functions.sh ${RPM_BUILD_ROOT}%{_libexecdir}/pivauth/functions.sh

%clean
rm -rf ${RPM_BUILD_ROOT}

%pre
getent group pivauth >/dev/null || groupadd -r pivauth
getent passwd pivauth >/dev/null || \
    useradd -r -g pivauth -d /var/cache/pivauth -s /sbin/nologin \
    -c "Service account for SSH pivauth" pivauth
exit 0

%files
%attr(0755,root,root) %{_bindir}/pubkey2ssh
%attr(0755,root,root) %{_sbindir}/pivauth
%attr(0755,root,root) %{_libexecdir}/pivauth/functions.sh
%attr(0755,root,root) %{_docdir}/%{name}-%{version}

%attr(0700,pivauth,pivauth) %{_localstatedir}/cache/pivauth
