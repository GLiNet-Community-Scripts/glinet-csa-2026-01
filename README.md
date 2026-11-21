<div align="center">

<img src="images/logo.svg" width="300" alt="A seal resting on a patched-up router">

## gl-helper Triage for GL.iNet Routers and KVMs

**Check a device for the malware from GL.iNet's security notice of 20 November 2026, save the evidence, then clean up.**

[![Advisory CSA-2026-01](https://img.shields.io/badge/Advisory-CSA--2026--01-b3261e?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/) [![Guide](https://img.shields.io/badge/Guide-gl--i.net-16774c?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/fix/) [![License](https://img.shields.io/github/license/admonstrator/glinet-csa-2026-01?style=for-the-badge)](LICENSE) [![Last Commit](https://img.shields.io/github/last-commit/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/commits) [![Issues](https://img.shields.io/github/issues/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/issues) [![Stars](https://img.shields.io/github/stars/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/stargazers)

</div>

---

> [!WARNING]
> **Community work, not an official GL.iNet tool.** GL.iNet has not reviewed or endorsed it.
> It finds and removes only the indicators we know of, and it **does not replace the factory
> reset** GL.iNet recommends. Use it at your own risk.

---

## 📖 About

On 20 November 2026 GL.iNet published a [security notice](https://www.gl-inet.com/blogs/blog/glinet-security-notice-2026-11-20):
its cloud remote management service had been abused to install malware on a subset of
GL.iNet routers and KVM devices. The community advisory is
[CSA-2026-01](https://gl-i.net/security/csa-2026-01/).

This repository contains a triage script for the implant known as "gl-helper". It runs on
GL.iNet KVMs (RM1 family, buildroot based) and on GL.iNet / OpenWrt routers.

Created by [Admon](https://forum.gl-inet.com/u/admon/) for the GL.iNet community.

> 🎖️ **Community Maintained** – Part of the [GL.iNet Toolbox](https://github.com/Admonstrator/glinet-toolbox) project  
> ⚠️ **Independent Project** – Not affiliated with GL.iNet

---

## ✨ Features

- 🔎 **Check** – Read-only detection of the known indicators of the implant
- 📦 **Archive** – Saves evidence before anything is changed. No archive, no changes.
- 🧹 **Fix** – Removes the known implant files and their persistence on request
- 🛡️ **Trusted tools** – Uses the busybox from the read-only base image, not the tools an attacker may have replaced
- 👀 **Review list** – Reports other unusual changes for a human to judge and never touches them
- 🖥️ **Routers and KVMs** – GL.iNet / OpenWrt routers and GL.iNet KVMs (RM1 family)

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| **Device** | GL.iNet KVM (RM1 family) or GL.iNet / OpenWrt router, with root SSH access |
| **On the device** | busybox `sh`/`ash` or bash, nothing to install |
| **On your computer** | Only for `triage-remote.sh`: Linux with bash, ssh, tar and sha256sum |

---

## 🔎 Indicators

The indicators come from the cleanup GL.iNet shipped in RM1PE firmware **1.10.2**
(`/etc/init.d/S08overlayfs`, built 2026-11-21). At boot it scrubs the writable overlay
layer when one of these marker files exists:

| Marker files (any one triggers) | Persistence removed together with them |
|---|---|
| `/etc/glinet/.cache/gl-helper` | `/etc/glinet/.cache/` |
| `/etc/glinet/.cache/gb` | `/etc/config/.gl/` |
| `/etc/config/.gl/gl-helper` | `/etc/rc.local` |
| `/etc/config/.gl/gb` | `/etc/crontabs/root` |
| | `/usr/bin/netstat` (a replaced, trojanized netstat) |

The vendor cleanup only runs when a marker file is present and only touches this set.
This script also detects:

- busybox/coreutils applets in the overlay that were replaced by a foreign regular file
  (for example `netstat`), unless a package (apk/opkg) installed the file,
- running processes started from implant paths or from a replaced applet,
- autostart and config files that reference implant paths: crontabs, `rc.local`, init
  scripts, hotplug, profile, and **sysupgrade keep lists** (an entry there makes the
  implant survive a firmware update with "keep settings"),
- implant persistence even when the marker files were deleted.

It also lists other overlay changes as `REVIEW` for a human to judge: new or modified
binaries, new init scripts, `authorized_keys`, extra uid 0 accounts, hidden files and
processes running from deleted binaries.

> ⚠️ **Do not run `netstat` on a device you suspect.** It may be the implant's replacement.
> The script never calls it and uses the busybox from the read-only base image (`/rom`)
> for its own tools.

---

## 🚀 Quick Start

Run the check on the device (SSH as root), without cloning the repository:

```bash
wget -q https://app.gl-i.net/csa-2026-01-fix -O gl-helper-triage.sh ; sh gl-helper-triage.sh
```

This only reads. It changes nothing and prints a report.

> ⚠️ **Read the script before you run it.** It runs as root on a device you suspect is compromised.

If the report shows indicators, save the evidence and then clean up:

```bash
sh gl-helper-triage.sh --archive
```

```bash
sh gl-helper-triage.sh --fix
```

`--fix` writes the evidence archive first and aborts if that fails. On the device `/tmp`
is RAM: copy the archive to your computer before you reboot.

### From Your Computer

`triage-remote.sh` runs the check over SSH, streams the evidence archive to `./evidence/`
on your computer, verifies it and only then runs `--fix`. It needs Linux with bash, ssh,
tar and sha256sum. Several devices can be given at once.

```bash
git clone https://github.com/admonstrator/glinet-csa-2026-01.git
cd glinet-csa-2026-01
./triage-remote.sh root@192.168.8.1          # check + pull the evidence archive
./triage-remote.sh --fix root@192.168.8.1    # also remediate if indicators are found
```

Or pipe the script through SSH yourself, so nothing is stored on the device:

```bash
ssh root@DEVICE 'sh -s -- --check' < gl-helper-triage.sh
ssh root@DEVICE 'sh -s -- --archive --stdout' < gl-helper-triage.sh > evidence.tar.gz
ssh root@DEVICE 'sh -s -- --fix' < gl-helper-triage.sh
```

---

## 🎛️ Modes

| Option | Effect |
|---|---|
| `--check` (default) | Read-only detection and report |
| `--archive [-o DIR]` | Report plus evidence archive in `DIR` (default `/tmp`) |
| `--archive --stdout` | Evidence archive to stdout, log to stderr |
| `--fix [-o DIR]` | Archive first (aborts if that fails), then remediate and re-check |
| `--color`, `--no-color` | Force or disable coloured output. By default colours are used only on a terminal; `NO_COLOR=1` also turns them off. |

Exit codes: `0` clean, `1` indicators found, `2` fixed and clean, `3` fix incomplete,
`4` error.

The report groups its findings by label and ends with a summary and a verdict. The copy
in the evidence archive is always plain text.

Findings are labeled:

- `IOC`: a known indicator. `--fix` removes it.
- `PERSIST`: `rc.local` or root crontab in the overlay without an implant reference.
  `--fix` resets it only when an IOC was found, like the vendor cleanup.
- `REVIEW`: unusual change. Archived and reported, never modified.
- `INFO`: context, for example files installed by a package.

---

## 🧹 What `--fix` Does

1. Writes and verifies the evidence archive. No archive, no changes.
2. Stops implant processes (SIGSTOP all, then SIGKILL).
3. Removes `/etc/glinet/.cache/` and `/etc/config/.gl/`.
4. Resets `rc.local` and the root crontab to the base image version, or removes them
   if the base image has none. The previous versions are in the archive.
5. Restores replaced applets from the base image and removes other autostart files that
   start the implant, including OpenWrt `rc.d` links to removed init scripts.
6. Removes only the implant lines from sysupgrade keep lists.
7. Restarts cron and checks again.

Changes go through the merged root filesystem, so the overlay stays consistent while it
is mounted. `REVIEW` items are never touched.

---

## 📦 Evidence Archive

`gl-triage-<host>-<time>.tar.gz` contains the report, the findings, a listing and
SHA-256 hashes of the whole overlay upper layer, a full copy of the upper layer (up to
64 MiB), copies of all finding paths, process list with socket owners, decoded TCP
connections, `/proc/<pid>/` data and the binary of implant processes, kernel and system
logs, and a `MANIFEST.sha256`.

> ⚠️ **The archive contains device configuration, possibly including Wi-Fi keys, VPN keys and
> other secrets.** Treat it as sensitive and do not post it publicly.

Password hashes are not included; the archive only records whether a hash differs from the base image.

On the device `/tmp` is RAM. Copy the archive off the device before rebooting.

---

## ✅ After Triage

- Keep the evidence archive.
- KVM: update to fixed firmware. RM1PE 1.10.2 runs the vendor cleanup at every boot.
- Router: update **without keeping settings**. OpenWrt keeps `/etc/config` across a
  sysupgrade, and the implant hides in `/etc/config/.gl`.
- A factory reset wipes the whole overlay and is the safe option on both.
- Check the computer attached to a KVM, and the clients behind a router.
- Change the device password, the GL.iNet cloud account password and SSH keys.

---

## 🧬 Firmware Notes

From the firmware images we compared (1.10.1 vs 1.10.2; both 1.10.2 builds are from 2026-11-21):

- **RM1PE 1.10.2** contains the boot cleanup in `/etc/init.d/S08overlayfs`.
- **RM1V2 1.10.2** does not contain it. Its `S08overlayfs` is unchanged.
- Both 1.10.2 builds change `rtty` (the cloud remote terminal): the `-s`, `-C/--cacert`
  and `-x/--insecure` options are gone, the CA path `/var/run/gl-rtty/ca.crt` is built
  in, and `S99rtty` no longer reads a `tls` setting from the cloud-provided config.

---

## 🧪 Tests

The tests mount real overlay filesystems in an unprivileged user namespace, plant an
infection and run check, archive and fix:

```sh
unshare -rm bash tests/run-tests.sh
KVM_LOWER=/path/to/extracted/rm1pe-1.10.2/rootfs unshare -rm bash tests/run-tests.sh
```

Without `KVM_LOWER` only the OpenWrt scenarios run (synthetic base image). The script
was also run in check and archive mode on a GL.iNet router with firmware 4.11
(OpenWrt 25.12).

---

## 🚧 Limitations

- Only known indicators are remediated. A different implant variant, or other changes
  an attacker made, may remain. Read the `REVIEW` items.
- Without a read-only base image (`/rom`) the results are less precise and the tools come
  from `$PATH`.
- The script cannot see anything outside the device, such as changes on an attached
  computer or on the cloud account.

---

## 💡 Getting Help

- 📘 [Guide on gl-i.net](https://gl-i.net/security/csa-2026-01/fix/) – The steps on one page
- 🛡️ [Advisory CSA-2026-01 on gl-i.net](https://gl-i.net/security/csa-2026-01/) – What happened and what GL.iNet recommends
- 💬 [GL.iNet's notice in the forum](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056) – Discussion and updates from GL.iNet
- 🐛 [Report issues on GitHub](https://github.com/admonstrator/glinet-csa-2026-01/issues) – Bugs and false positives. Never attach an evidence archive.
- 📧 GL.iNet support (support@gl-inet.com) – If you are not sure whether your device is affected

---

## ⚠️ Disclaimer

This script is provided **as-is** without any warranty. Use it at your own risk.

It changes files on your device when you run it with `--fix`. It is a stopgap: it cannot
prove that a device is clean, and a factory reset is still recommended.

In a business network, talk to your cyber insurer or incident response provider before you
change or reset the device.

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

<div align="center">

## 🧰 Part of the GL.iNet Toolbox

[![GL.iNet Toolbox](https://img.shields.io/badge/🧰_GL.iNet_Toolbox-Explore_All_Tools-blue?style=for-the-badge)](https://github.com/Admonstrator/glinet-toolbox)

**Made with ❤️ by [Admon](https://github.com/Admonstrator) for the GL.iNet Community**

</div>
