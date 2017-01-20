Name:           backup_ldap
Version:	0.9.2
Release:	1%{?dist}
Summary:	Simple 389 ds backup utility

#Group:		
License:	ASL 2.0
URL:		https://github.com/cviecco/backup_ldap/
Source0:	backup_ldap-%{version}.tar.gz

#BuildRequires:	golang
#Requires:	

#no debug package as this is go
%define debug_package %{nil}

%description
Simple encryption using clound infrastrcture


%prep
%setup -n %{name}-%{version}

%build
go build -ldflags "-X main.Version=%{version}" backup_ldap.go 


%install
#%make_install
%{__install} -Dp -m0755 backup_ldap %{buildroot}%{_sbindir}/backup_ldap
install -d %{buildroot}/usr/lib/systemd/system
install -p -m 0644 ./backup-ldap.service %{buildroot}/usr/lib/systemd/system/backup-ldap.service

%post
chown nobody /%{_sbindir}/backup_ldap
chgrp nobody /%{_sbindir}/backup_ldap
chmod u+s /%{_sbindir}/backup_ldap
systemctl daemon-reload

%postun
systemctl daemon-reload

%files
#%doc
%{_sbindir}/backup_ldap
/usr/lib/systemd/system/backup-ldap.service


%changelog

