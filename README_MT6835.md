# HakiOS MT6835 (Redmi 13C 5G / POCO M6 5G — `air`)

Complete guide to build, flash, and boot Apple's XNU kernel (iOS 16.5 userland) on MediaTek MT6835 / Dimensity 6100+ (`air`).

---

## 1. Overview & Current Milestone

This project brings Apple's open-source XNU kernel (xnu-8796.121.2) and iOS 16.5 userland components onto the **Redmi 13C 5G** / **POCO M6 5G** (MediaTek Dimensity 6100+ / MT6835).

### What is Achieved & Verified:
- **EDK2 UEFI Boot**: Custom UniXNU UEFI firmware boots via `boot-air-shimed.img`.
- **DarwinBoot Handoff**: Safely drops EL2 to EL1h and transitions control to XNU.
- **Embedded ADT & DTB**: Apple Device Tree dynamically passed to XNU with fixed RAM physical apertures (`0x40000000`–`0x140000000`).
- **Framebuffer Console**: Hardware framebuffer display at 720×1600 (stride 2944 bytes) fully rendered in live text mode.
- **BSD & Core Subsystems**: Virtual memory bootstrap, pmap, early random, Skywalk subsystem, vfs, and devfs successfully initialized.
- **RAMDisk APFS Root**: APFS container on `/dev/md0` mounted read-only at `/`.
- **PID 1 Userland Execution**: `/sbin/init` started as PID 1, running diagnostic suites, kernel log dumping, and sysctl interfaces.
- **UFS 2.2 Controller**: MMIO `0x11260000` mapped, link synchronized via `DME_LINK_STARTUP` (0x16), and auto-hibernate disabled.

---

## 2. Repository Layout

The workspace is organized into three cooperating repositories:

```
hackios/
├── hackios-mt6835/         # Platform tools, UEFI repackers, kernel patchers (branch: main)
│   ├── configs/            # Device configurations
│   ├── prebuilt/           # Prebuilt UEFI binaries and KeypadDeviceDxe
│   ├── tools/              # Python repack & patch tools
│   └── rebuild.sh          # Standalone build script
├── hakios-xnu-kernel/      # XNU kernel tree & Darwin userland (branch: mtk)
│   ├── bsd/dev/            # MediaTek UFS driver (redwood_mtk_ufs.c)
│   └── userland/           # Custom init, libmini, rc.launchd, and root.apfs
├── hackios-uefi/           # EDK2 UEFI port for MT6835 (branch: main)
├── out/                    # Build outputs, payloads, and final boot images
└── rebuild.sh              # Top-level one-command builder
```

### Git Remotes:
- **`hackios-mt6835`**: `https://github.com/suchit-7x/hakios-mt6835.git` (`main`)
- **`hakios-xnu-kernel`**: `https://github.com/suchit-7x/hakios-xnu-kernel.git` (`mtk`)
- **`hackios-uefi`**: `https://github.com/suchit-7x/hackios-uefi.git` (`main`)

---

## 3. Host System Requirements

Builds are performed on Linux (Ubuntu 22.04+ or Debian 12+ recommended).

### Required System Packages:
```bash
sudo apt update
sudo apt install -y \
    build-essential \
    python3 \
    python3-pip \
    gcc-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
    dosfstools \
    liblzma-dev \
    git \
    fastboot
```

### Required Python Packages:
```bash
pip3 install pyfatfs
```

---

## 4. Setup & Clone

Clone all repositories into a common root workspace:

```bash
mkdir -p ~/hackios && cd ~/hackios

# 1. Clone platform repo
git clone https://github.com/suchit-7x/hakios-mt6835.git hackios-mt6835

# 2. Clone XNU kernel repo (branch mtk)
git clone -b mtk https://github.com/suchit-7x/hakios-xnu-kernel.git hakios-xnu-kernel

# 3. Clone UEFI repo
git clone https://github.com/suchit-7x/hackios-uefi.git hackios-uefi

# 4. Copy top-level rebuild script
cp hackios-mt6835/rebuild.sh ./
chmod +x rebuild.sh
```

---

## 5. Building the Images

Run the top-level rebuild script from the workspace directory:

```bash
./rebuild.sh
```

### What `rebuild.sh` does:
1. **[1/4] Kernel Diagnostics & Fixes** (`tools/patch_kernel_diagnostics.py`):
   - Patches `mach.development.bcm2837.orig` -> `mach.development.bcm2837`.
   - Injects framebuffer diagnostics, TTBR0 early mappings, and panic logger.
   - Embeds the Apple Device Tree (`KERNEL.adt`) with 4 MiB RAMDisk descriptors.
   - Clamps physical memory aperture to 4 GB (`0x40000000`–`0x140000000`).
   - Hooks UFSHCI initialization: disables Auto-Hibernate (`REG_AHIT = 0`), issues `DME_LINK_STARTUP` (0x16) twice to sync UniPro link, and registers the two-tier UFS recovery hook.
2. **[2/4] FAT32 MBR RAMDisk Generation** (`tools/build_air_ramdisk.py`):
   - Formats a 37 MiB FAT32 partition aligned to LBA 2048 with clusters >= 65,525.
   - Populates UniXNU configuration (`unixnu.toml`), kernel payload (`mach.development.bcm2837`), device tree (`air.dtb`), ADT, and `root.apfs`.
   - Runs `fsck.fat` to ensure clean BPB/FSInfo headers.
   - Wraps the partition into an MBR partitioned disk (`air_ramdisk.img`, 45,088,768 bytes).
3. **[3/4] Vendor Boot Packaging** (`tools/build_vendor_boot.py`):
   - Repacks Android boot header v4 with the new 43 MiB ramdisk.
   - Generates `vendor_boot_b.img` (67,108,864 bytes).
4. **[4/4] UEFI Repack & Shim Generation** (`tools/repack_uefi.py`):
   - Decompresses FVMAIN LZMA stream from `uefi_kernel.bin`.
   - Injects `KeypadDeviceDxe.pe` for volume key navigation in UniXNU.
   - Patches DarwinBoot RAMDisk validation check to bypass `EFI_COMPROMISED_DATA`.
   - Injects EL2->EL1 handoff stub and visual boot stages.
   - Recompresses using standard EDK2 LZMA and outputs `boot-air-shimed.img` (67,108,864 bytes).

---

## 6. Flashing & Booting the Device

> [!CAUTION]
> **SAFETY RULES FOR MT6835**:
> 1. **ONLY FLASH TO SLOT `_b`**: `vendor_boot_b` and `boot_b`.
> 2. **NEVER TOUCH SLOT `_a`**: Slot `_a` contains your stock factory Android firmware.
> 3. **NEVER EXECUTE `fastboot reboot recovery`**: Booting recovery on slot `_b` can cause bootloops. Always reboot directly (`fastboot reboot`).

### Flashing Procedure:
Put device into Fastboot mode (`Power` + `Volume Down`):

```bash
# Verify device is detected in fastboot
fastboot devices

# Flash images strictly to slot _b
fastboot flash vendor_boot_b out/vendor_boot_b.img
fastboot flash boot_b out/boot-air-shimed.img

# Set slot _b as active and reboot
fastboot --set-active=b
fastboot reboot
```

To return to stock Android at any time:
```bash
fastboot --set-active=a
fastboot reboot
```

---

## 7. Rebuilding Userland (`root.apfs`)

If you want to modify userland programs (e.g. `/sbin/init`, `libmini`, or `rc.launchd`):

1. Edit sources in `hakios-xnu-kernel/userland/src/`.
2. Build the userland image:
   ```bash
   cd ~/hackios/hakios-xnu-kernel/userland
   PREBUILT=1 ./build.sh
   ```
3. Copy the updated `root.apfs` to `out/`:
   ```bash
   cp root.apfs ~/hackios/out/root.apfs
   ```
4. Run `./rebuild.sh` from `~/hackios/` to regenerate `vendor_boot_b.img` and `boot-air-shimed.img`.
