# Daemon package for Fedora and openSUSE. The GUI RPM is produced by the Tauri
# bundler (`npx tauri build --bundles rpm`) and depends on this package.
# Build: cp packaging/linux/alizy.sysusers ~/rpmbuild/SOURCES/ &&
#        rpmbuild -bb packaging/rpm/alizyd.spec --define "_srcroot $PWD"
Name:           alizyd
Version:        0.2.1
Release:        1%{?dist}
Summary:        Alizy VPN service: WireGuard, nftables kill switch, split tunnelling
License:        GPL-3.0-or-later
URL:            https://github.com/jonios/alizy
Source1:        alizy.sysusers
Requires:       wireguard-tools nftables polkit systemd
%if 0%{?suse_version}
Requires:       iproute2
%else
Requires:       iproute
%endif
Recommends:     openresolv
Recommends:     openssh-clients badvpn
%{?systemd_requires}

%description
Privileged system service used by the Alizy desktop client. Manages kernel
WireGuard interfaces, an isolated nftables table (inet alizy) for the kill
switch and IPv4/IPv6/DNS leak protection, and split-tunnel routing.

%install
install -Dm755 %{_srcroot}/target/release/alizyd %{buildroot}%{_bindir}/alizyd
install -Dm644 %{_srcroot}/packaging/linux/alizyd.service %{buildroot}%{_unitdir}/alizyd.service
install -Dm644 %{_srcroot}/packaging/linux/alizy.sysusers %{buildroot}%{_sysusersdir}/alizy.conf
install -Dm644 %{_srcroot}/packaging/linux/io.alizy.policy %{buildroot}%{_datadir}/polkit-1/actions/io.alizy.policy

%pre
%sysusers_create_compat %{SOURCE1}

%post
%systemd_post alizyd.service

%preun
%systemd_preun alizyd.service
if [ $1 -eq 0 ]; then %{_bindir}/alizyd --remove-firewall || :; fi

%postun
%systemd_postun_with_restart alizyd.service

%files
%{_bindir}/alizyd
%{_unitdir}/alizyd.service
%{_sysusersdir}/alizy.conf
%{_datadir}/polkit-1/actions/io.alizy.policy
