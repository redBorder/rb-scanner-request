%global rb_bin_path "/var/rb-scanner-request/bin/"
%global rb_redborder_bin "/usr/lib/redborder/bin/"
%global rb_redborder_scripts "/usr/lib/redborder/scripts/"

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

BuildRequires: golang = 1.15.14
BuildRequires: glide

%description
%{summary}

%prep

%setup -qn %{name}-%{version}

%build

%install
ls
mkdir -p %{buildroot}%{rb_bin_path}
#mkdir -p %{buildroot}/usr/lib/systemd/system/
export GOPATH=/builddir/build/BUILD/%{name}-%{version}
export GOBIN=/usr/lib/golang/bin/go
export GOROOT=/usr/lib/golang


export PATH=$PATH:$GOROOT/bin

export PATH=$PATH:$GOBIN
export PATH=$PATH:$GOPATH

cd src
cd rb-scanner-request
(make)
install -D -m 0755 rb-scanner-request %{buildroot}%{rb_bin_path}/rb-scanner-request

cd ../../service
install -D -m 644 redborder-scanner.service %{buildroot}/usr/lib/systemd/system/redborder-scanner.service

cd ../service/scripts
install -D -m 644 rb_scan_vulnerabilities.sh %{buildroot}%{rb_redborder_bin}rb_scan_vulnerabilities.sh
install -D -m 644 rb_scan_vulnerabilities.rb %{buildroot}%{rb_redborder_bin}rb_scan_vulnerabilities.rb

%pre

%post

%files
%defattr(0755,root,root)
%{rb_bin_path}
%defattr(644,root,root)
/usr/lib/systemd/system/redborder-scanner.service

%doc

%changelog
* Fri Nov 26 2021 Javier Rodriguez Gomez <javiercrg@redborder.com> - 0.0.1
- First spec version
