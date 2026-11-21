#!/bin/bash
# Tests for gl-helper-triage.sh on real overlayfs mounts inside an unprivileged user
# namespace (no root needed, Linux >= 5.11):
#
#   unshare -rm bash tests/run-tests.sh
#   KVM_LOWER=/path/to/extracted/rm1pe-1.10.2/rootfs unshare -rm bash tests/run-tests.sh
#
# The OpenWrt scenarios use a small synthetic base image. The KVM scenarios need the
# extracted rootfs of a GL.iNet KVM firmware (e.g. RM1PE 1.10.2) in KVM_LOWER.
set -u
T=$(cd "$(dirname "$0")/.." && pwd)/gl-helper-triage.sh
KVM_LOWER=${KVM_LOWER:-}
BASE=$(mktemp -d)
trap 'umount "$BASE"/*/m 2>/dev/null; rm -rf "$BASE"' EXIT
pass=0 fail=0
ok()  { echo "  PASS: $*"; pass=$((pass+1)); }
bad() { echo "  FAIL: $*"; fail=$((fail+1)); }
expect() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkscen() { # name lower
	local d=$BASE/$1
	mkdir -p "$d/u" "$d/w" "$d/m" "$d/out"
	mount -t overlay overlay -o "lowerdir=$2,upperdir=$d/u,workdir=$d/w" "$d/m"
	umount "$d/m"
	echo "$d"
}
mnt() { mount -t overlay overlay -o "lowerdir=$2,upperdir=$1/u,workdir=$1/w" "$1/m"; }
run() { # dir lower mode...
	local d=$1 lo=$2; shift 2
	sh "$T" --root "$d/m" --upper "$d/u" --lower "$lo" -o "$d/out" "$@"
}

# ------------------------------------------------------------ OpenWrt base image
OWL=$BASE/openwrt-rom
mkdir -p "$OWL"/{etc/init.d,etc/rc.d,bin,usr/bin,lib/apk/db,etc/crontabs}
echo "DISTRIB_ID='OpenWrt'" >"$OWL/etc/openwrt_release"
printf '# Put your custom commands here\nexit 0\n' >"$OWL/etc/rc.local"
printf '#!/bin/sh\n' >"$OWL/etc/init.d/cron"; printf '#!/bin/sh\n' >"$OWL/etc/init.d/dnsmasq"
printf 'root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\n' >"$OWL/etc/passwd"
echo dummy >"$OWL/bin/busybox"; ln -s busybox "$OWL/bin/netstat"; ln -s busybox "$OWL/bin/login"
mkdir -p "$OWL/etc/uci-defaults"; echo 'uci commit' >"$OWL/etc/uci-defaults/10_firstboot"
printf 'P:busybox\nF:bin\nR:busybox\n\n' >"$OWL/lib/apk/db/installed"
echo openwrt >"$OWL/etc/hostname"

if [ -n "$KVM_LOWER" ]; then
echo "=== 1. KVM (RM1PE 1.10.2 base), infected"
D=$(mkscen kvm "$KVM_LOWER"); U=$D/u
mkdir -p "$U"/etc/glinet/.cache "$U"/etc/config/.gl "$U"/etc/crontabs "$U"/usr/bin "$U"/bin "$U"/root/.ssh "$U"/etc/init.d
printf '#!/bin/sh\nwhile :; do sleep 60; done\n' >"$U/etc/glinet/.cache/gl-helper"; chmod 755 "$U/etc/glinet/.cache/gl-helper"
echo payload >"$U/etc/glinet/.cache/gb"; echo payload >"$U/etc/config/.gl/gb"
echo '/etc/glinet/.cache/gl-helper &' >"$U/etc/rc.local"
echo '*/5 * * * * /etc/config/.gl/gb >/dev/null 2>&1' >"$U/etc/crontabs/root"
printf '#!/bin/sh\n# trojan netstat\n' >"$U/usr/bin/netstat"; chmod 755 "$U/usr/bin/netstat"
printf 'fake ls\n' >"$U/bin/ls"; chmod 755 "$U/bin/ls"
cp "$KVM_LOWER/usr/bin/wget" "$U/usr/bin/wget"; echo x >>"$U/usr/bin/wget"
echo 'ssh-ed25519 AAAA attacker' >"$U/root/.ssh/authorized_keys"
printf '#!/bin/sh\n/etc/glinet/.cache/gl-helper\n' >"$U/etc/init.d/S99update-helper"
{ cat "$KVM_LOWER/etc/passwd"; echo 'backdoor:x:0:0::/root:/bin/sh'; } >"$U/etc/passwd"
echo note >"$U/etc/.hidden-note"
cp -a "$KVM_LOWER/etc/hostname" "$U/etc/hostname" 2>/dev/null
mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
cat "$D/check.txt"
expect "check exit 1 (infected)" '[ $rc = 1 ]'
expect "3 markers" '[ $(grep -c "^ *IOC  *marker" "$D/check.txt") = 3 ]'
expect "netstat + ls hijack" 'grep -q "applet-hijack *\/usr\/bin\/netstat" "$D/check.txt" && grep -q "applet-hijack *\/bin\/ls" "$D/check.txt"'
expect "rc.local + crontab + init script reference IOC" '[ $(grep -c "persist-ref" "$D/check.txt") = 3 ] && grep -q "persist-ref *\/etc\/init.d\/S99update-helper" "$D/check.txt"'
expect "wget = REVIEW modified-binary" 'grep -q "REVIEW  *modified-binary *\/usr\/bin\/wget" "$D/check.txt"'
expect "authorized_keys + hidden = REVIEW" 'grep -q "REVIEW  *new *\/root\/.ssh\/authorized_keys" "$D/check.txt" && grep -q "hidden-note" "$D/check.txt"'
expect "uid0 backdoor account" 'grep -A1 "uid0-account" "$D/check.txt" | grep -q backdoor'
expect "identical copy-up (hostname) ignored" '! grep -q "/etc/hostname" "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >"$D/fix.txt"; rc=$?
sed -n '/== Remediation/,$p' "$D/fix.txt"
expect "fix exit 2 (clean afterwards)" '[ $rc = 2 ]'
A=$(ls "$D"/out/gl-triage-*.tar.gz 2>/dev/null | head -1)
expect "archive exists + sha256 ok" '[ -n "$A" ] && (cd "$D/out" && sha256sum -c "${A##*/}.sha256" >/dev/null)'
expect "archive has implant + trojan netstat + crontab" 'tar -tzf "$A" | grep -q "files/upper/etc/glinet/.cache/gl-helper" && tar -tzf "$A" | grep -q "files/upper/usr/bin/netstat" && tar -tzf "$A" | grep -q "files/merged/etc/crontabs/root"'
expect "archive MANIFEST verifies" 'mkdir -p "$D/x" && tar -C "$D/x" -xzf "$A" && (cd "$D/x/evidence" && sha256sum -c MANIFEST.sha256 >/dev/null)'
expect "markers gone" '[ ! -e "$D/m/etc/glinet/.cache" ] && [ ! -e "$D/m/etc/config/.gl" ]'
expect "rc.local + crontab gone (not in base)" '[ ! -e "$D/m/etc/rc.local" ] && [ ! -e "$D/m/etc/crontabs/root" ]'
expect "netstat restored as busybox symlink" '[ -L "$D/m/usr/bin/netstat" ] && [ "$(readlink "$D/m/usr/bin/netstat")" = "$(readlink "$KVM_LOWER/usr/bin/netstat")" ]'
expect "ls restored as coreutils symlink" '[ -L "$D/m/bin/ls" ] && [ "$(readlink "$D/m/bin/ls")" = coreutils ]'
expect "implant init script removed" '[ ! -e "$D/m/etc/init.d/S99update-helper" ]'
expect "REVIEW items untouched (wget, keys)" '[ -f "$D/m/root/.ssh/authorized_keys" ] && ! cmp -s "$D/m/usr/bin/wget" "$KVM_LOWER/usr/bin/wget"'
run "$D" "$KVM_LOWER" --check >/dev/null; rc=$?
expect "re-check after fix: exit 0" '[ $rc = 0 ]'
umount "$D/m"
else
	echo "=== 1. KVM: skipped (set KVM_LOWER)"
fi

echo; echo "=== 2. OpenWrt router, infected"
D=$(mkscen owrt "$OWL"); U=$D/u
mkdir -p "$U"/etc/config/.gl "$U"/etc/crontabs "$U"/usr/bin "$U"/etc/rc.d "$U"/etc/init.d "$U"/etc/dropbear
echo x >"$U/etc/config/.gl/gl-helper"; echo x >"$U/etc/config/.gl/gb"
echo '0 3 * * * /etc/config/.gl/gl-helper' >"$U/etc/crontabs/root"
printf '/usr/bin/my-led-script\nexit 0\n' >"$U/etc/rc.local"
printf 'trojan\n' >"$U/usr/bin/netstat"; chmod 755 "$U/usr/bin/netstat"
ln -s ../init.d/dnsmasq "$U/etc/rc.d/S19dnsmasq"
printf '#!/bin/sh\n' >"$U/etc/init.d/gl-update"; ln -s ../init.d/gl-update "$U/etc/rc.d/S99gl-update"
echo key >"$U/etc/dropbear/dropbear_ed25519_host_key"
printf '/etc/my-own-file\n/etc/config/.gl/\n' >"$U/etc/sysupgrade.conf"
printf '#!/bin/sh /etc/rc.common\nstart() { /etc/config/.gl/gl-helper & }\n' >"$U/etc/init.d/glhelper"; ln -s ../init.d/glhelper "$U/etc/rc.d/S95glhelper"
mkdir -p "$U/bin"; ln -s /bin/busybox "$U/bin/login"
mnt "$D" "$OWL"
rm "$D/m/etc/uci-defaults/10_firstboot"   # overlay creates a whiteout, like OpenWrt after first boot
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
cat "$D/check.txt"
expect "whiteout really created" '[ -c "$U/etc/uci-defaults/10_firstboot" ]'
expect "whiteout (deleted uci-defaults) not reported" '! grep -q "10_firstboot" "$D/check.txt"'
expect "absolute vs relative symlink to busybox not reported" '! grep -q "/bin/login" "$D/check.txt"'
expect "check exit 1" '[ $rc = 1 ]'
expect "platform openwrt" 'grep -q "Platform  *openwrt" "$D/check.txt"'
expect "markers 2 + crontab + netstat + init script + keep list = 6 IOC" 'grep -q "Summary: IOC=6 " "$D/check.txt" && grep -q "keep-ref *\/etc\/sysupgrade.conf" "$D/check.txt"'
expect "custom rc.local = PERSIST (not IOC)" 'grep -q "PERSIST  *persistence *\/etc\/rc.local" "$D/check.txt"'
expect "known service link S19dnsmasq ignored" '! grep -q "S19dnsmasq" "$D/check.txt"'
expect "benign new service + rc.d link = REVIEW" 'grep -q "REVIEW  *new *\/etc\/rc.d\/S99gl-update" "$D/check.txt" && grep -q "REVIEW  *new *\/etc\/init.d\/gl-update" "$D/check.txt"'
expect "dropbear host key ignored" '! grep -q "host_key" "$D/check.txt"'
expect "recommendation warns about keep-settings" 'grep -q "WITHOUT keeping settings" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
sed -n '/== Remediation/,$p' "$D/fix.txt"
expect "fix exit 2" '[ $rc = 2 ]'
expect "rc.local restored to base content" 'cmp -s "$D/m/etc/rc.local" "$OWL/etc/rc.local"'
expect "netstat removed (not in base), /bin/netstat intact" '[ ! -e "$D/m/usr/bin/netstat" ] && [ -L "$D/m/bin/netstat" ]'
expect "crontab + .gl gone" '[ ! -e "$D/m/etc/crontabs/root" ] && [ ! -e "$D/m/etc/config/.gl" ]'
expect "implant service + its rc.d link removed, benign service kept" '[ ! -e "$D/m/etc/init.d/glhelper" ] && [ ! -L "$D/m/etc/rc.d/S95glhelper" ] && [ -f "$D/m/etc/init.d/gl-update" ] && [ -L "$D/m/etc/rc.d/S99gl-update" ] && [ -L "$D/m/etc/rc.d/S19dnsmasq" ]'
expect "sysupgrade.conf: only implant line removed" 'grep -qx "/etc/my-own-file" "$D/m/etc/sysupgrade.conf" && ! grep -q "\.gl" "$D/m/etc/sysupgrade.conf"'
expect "custom rc.local kept in archive" 'tar -xzOf "$(ls "$D"/out/*.tar.gz)" evidence/files/merged/etc/rc.local | grep -q my-led-script'
umount "$D/m"

if [ -n "$KVM_LOWER" ]; then
echo; echo "=== 3. Variant without markers (vendor cleanup would miss it)"
D=$(mkscen nomark "$KVM_LOWER"); U=$D/u
mkdir -p "$U"/etc/crontabs "$U"/usr/bin
echo '*/5 * * * * /etc/config/.gl/gb' >"$U/etc/crontabs/root"
printf 'trojan\n' >"$U/usr/bin/netstat"
mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary|Verdict' "$D/check.txt"
expect "detected without markers (exit 1, IOC=2)" '[ $rc = 1 ] && grep -q "Summary: IOC=2 " "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >/dev/null; rc=$?
expect "fixed (exit 2)" '[ $rc = 2 ] && [ ! -e "$D/m/etc/crontabs/root" ] && [ -L "$D/m/usr/bin/netstat" ]'
umount "$D/m"

echo; echo "=== 4. Clean KVM"
D=$(mkscen clean "$KVM_LOWER"); mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
grep -E 'Summary|Verdict' "$D/check.txt"
expect "clean: exit 0, IOC=0" '[ $rc = 0 ] && grep -q "Summary: IOC=0 " "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >"$D/fix.txt"; rc=$?
expect "fix on clean device changes nothing, exit 0" '[ $rc = 0 ] && grep -q "nothing to remediate" "$D/fix.txt" && [ -z "$(ls -A "$D/u")" ]'
run "$D" "$KVM_LOWER" --archive --stdout >"$D/stdout.tar.gz" 2>"$D/stdout.log"; rc=$?
expect "--archive --stdout gives valid tar.gz, log on stderr" '[ $rc = 0 ] && tar -tzf "$D/stdout.tar.gz" | grep -q evidence/report.txt && grep -q "Verdict" "$D/stdout.log"'
umount "$D/m"
else
	echo "=== 3./4. KVM: skipped (set KVM_LOWER)"
fi

echo; echo "=== 5. OpenWrt, netstat installed by a package (apk) -> INFO only"
D=$(mkscen pkg "$OWL"); U=$D/u
mkdir -p "$U/usr/bin" "$U/lib/apk/db"
printf 'real netstat\n' >"$U/usr/bin/netstat"
{ cat "$OWL/lib/apk/db/installed"; printf 'P:net-tools-netstat\nF:usr/bin\nR:netstat\n\n'; } >"$U/lib/apk/db/installed"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary' "$D/check.txt"
expect "package netstat is INFO, exit 0" '[ $rc = 0 ] && grep -q "installed by package net-tools-netstat" "$D/check.txt"'
umount "$D/m"

echo; echo "=== 6. OpenWrt with opkg (firmware 4.x), netstat installed by a package -> INFO only"
OWO=$BASE/openwrt-rom-opkg
cp -a "$OWL" "$OWO"; rm -rf "$OWO/lib/apk"; mkdir -p "$OWO/usr/lib/opkg/info"
D=$(mkscen opkg "$OWO"); U=$D/u
mkdir -p "$U/usr/bin" "$U/usr/lib/opkg/info"
printf 'real netstat\n' >"$U/usr/bin/netstat"
printf '/usr/bin/netstat\n' >"$U/usr/lib/opkg/info/net-tools-netstat.list"
mnt "$D" "$OWO"
run "$D" "$OWO" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary' "$D/check.txt"
expect "opkg package netstat is INFO, exit 0" '[ $rc = 0 ] && grep -q "installed by package net-tools-netstat" "$D/check.txt"'
expect "no stray heading in the report" '! grep -q -- "== -n" "$D/check.txt"'
umount "$D/m"

echo; echo "=== 7. OpenWrt, firewall config changed and a new nftables include"
mkdir -p "$OWL/etc/config"
printf "config defaults\n\toption input 'REJECT'\n" >"$OWL/etc/config/firewall"
D=$(mkscen fw "$OWL"); U=$D/u
mkdir -p "$U/etc/config" "$U/etc/nftables.d"
printf "config defaults\n\toption input 'REJECT'\n\nconfig redirect\n\toption name 'evil'\n\toption dest_ip '10.9.9.9'\n" >"$U/etc/config/firewall"
printf '# comment\nchain x { tcp dport 22 accept }\n' >"$U/etc/nftables.d/10-x.nft"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
sed -n '/== Firewall/,/== Result/p' "$D/check.txt"
expect "changed firewall config = REVIEW with 3 new lines, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *fw-config  *\/etc\/config\/firewall" "$D/check.txt" && grep -q "3 lines that are not in it" "$D/check.txt"'
expect "new lines are listed, unchanged ones are not" 'grep -q "option dest_ip .10.9.9.9." "$D/check.txt" && ! grep -q "option input" "$D/check.txt"'
expect "new nftables include = REVIEW, comment not listed" 'grep -q "REVIEW  *fw-config  *\/etc\/nftables.d\/10-x.nft" "$D/check.txt" && grep -q "tcp dport 22 accept" "$D/check.txt" && ! grep -q "# comment" "$D/check.txt"'
run "$D" "$OWL" --archive >/dev/null
expect "firewall config is in the archive" 'tar -tzf "$(ls "$D"/out/*.tar.gz)" | grep -q "files/merged/etc/config/firewall"'
umount "$D/m"

echo; echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
