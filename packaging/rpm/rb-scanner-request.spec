%define _binaries_in_noarch_packages_terminate_build 0
%define _unpackaged_files_terminate_build 0

Name: rb-scanner-request
Version: %{__version}
Release: %{__release}%{?dist}
BuildArch: noarch
Summary: rpm used to install rb-scanner-request in a redborder ng

License: AGPL 3.0
URL: https://github.com/redBorder/rb-scanner-request
Source0: %{name}-%{version}.tar.gz

BuildRequires: go = 1.6.3
BuildRequires: glide rsync gcc
BuildRequires:	rsync mlocate

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build

export GOPATH=${PWD}/gopath
export PATH=${GOPATH}:${PATH}

mkdir -p $GOPATH/src/github.com/redBorder/rb-scanner-request
cd src/rb-scanner-request
rsync -az --exclude=gopath/ ./ $GOPATH/src/github.com/redBorder/rb-scanner-request
cd $GOPATH/src/github.com/redBorder/rb-scanner-request
make

%install
export PARENT_BUILD=${PWD}
export GOPATH=${PWD}/gopath
export PATH=${GOPATH}:${PATH}
cd $GOPATH/src/github.com/redBorder/rb-scanner-request
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/rb-scanner-request
mkdir -p %{buildroot}/etc/rb-scanner-request
prefix=%{buildroot}/usr make install

install -D -m 644 redborder-scanner.service %{buildroot}/usr/lib/systemd/system/redborder-scanner.service
install -D -m 644 rb_scan_vulnerabilities.sh %{buildroot}%/usr/lib/redborder/bin/rb_scan_vulnerabilities.sh
install -D -m 644 rb_scan_vulnerabilities.rb %{buildroot}%/usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb


%clean
rm -rf %{buildroot}

%pre

%post

%files
%defattr(0755,root,root)
/usr/bin/rb-scanner-request
%defattr(644,root,root)
/usr/lib/systemd/system/redborder-scanner.service
%defattr(755,root,root)
/usr/lib/redborder/bin/rb_scan_vulnerabilities.sh
%defattr(755,root,root)
/usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb

%doc

%changelog
* Fri Nov 26 2021 Javier Rodriguez Gomez <javiercrg@redborder.com> - 0.0.1
- First spec version
