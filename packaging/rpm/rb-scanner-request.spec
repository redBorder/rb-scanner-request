Name: rb-scanner-request
Version: %{__version}
Release: %{__release}%{?dist}

License: AGPL 3.0
URL: https://github.com/redBorder/rb-scanner-request
Source0: %{name}-%{version}.tar.gz

BuildRequires: go = 1.6.3
BuildRequires: glide rsync gcc git
BuildRequires:	rsync mlocate

Summary: rpm used to install rb-scanner-request in a redborder ng
Group:   Development/Libraries/Go

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
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/redborder/bin
mkdir -p %{buildroot}/usr/lib/redborder/scripts
mkdir -p %{buildroot}/usr/share/rb-scanner-request
mkdir -p %{buildroot}/etc/rb-scanner-request

export PARENT_BUILD=${PWD}
export GOPATH=${PWD}/gopath
export PATH=${GOPATH}:${PATH}
pushd $GOPATH/src/github.com/redBorder/rb-scanner-request
prefix=%{buildroot}/usr make install

popd
cp resources/bin/* %{buildroot}/usr/lib/redborder/bin
cp resources/scripts/* %{buildroot}/usr/lib/redborder/scripts

install -D -m 0644 resources/systemd/redborder-scanner.service %{buildroot}/usr/lib/systemd/system/redborder-scanner.service

%clean
rm -rf %{buildroot}

%pre

%post
/usr/lib/redborder/bin/rb_rubywrapper.sh -c
systemctl daemon-reload

%files
%defattr(0755,root,root)
/usr/bin/rb-scanner-request
%defattr(644,root,root)
/usr/lib/systemd/system/redborder-scanner.service
%defattr(755,root,root)
/usr/lib/redborder/bin/rb_scan_vulnerabilities.sh
%defattr(755,root,root)
/usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb
%defattr(755,root,root)
/usr/lib/redborder/bin/rb_host_discovery.sh
%defattr(755,root,root)
/usr/lib/redborder/scripts/rb_host_discovery.rb

%doc

%changelog
* Fri Nov 26 2021 Javier Rodriguez Gomez <javiercrg@redborder.com> - 0.0.1
- First spec version
