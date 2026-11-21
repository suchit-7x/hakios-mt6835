#!/usr/bin/env python3
"""
Pack xnu-flashed-slot_a.img: mtkloader, then Android's kernel, then the XNU payload, in the
Android boot image (~/firmware/air/boot.img by default on MT6835 air; its ramdisk, dtb and cmdline
are kept). Booting it runs XNU once, then Android comes back with XNU's log in
/sys/fs/pstore/console-ramoops-0 (see mtkloader/mtkloader.c).

  build_flashed.py [android-boot.img]
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

default_boot = os.path.expanduser('~/firmware/air/boot.img')
if not os.path.isfile(default_boot):
    default_boot = os.path.join(ROOT, 'backup', 'boot_a_magisk.img')

android = sys.argv[1] if len(sys.argv) > 1 else default_boot
prog = os.path.join(HERE, 'mtkloader.bin')
if not os.path.isfile(prog):
    prog = os.path.join(HERE, 'fbdiag.bin')

payload = os.path.join(ROOT, 'build-payload.bin')
cmd = [sys.executable, os.path.join(ROOT, 'tools', 'chainboot.py'), android,
       prog, os.path.join(ROOT, 'xnu-flashed-slot_a.img')]
if os.path.isfile(payload):
    cmd.append(payload)

subprocess.check_call(cmd)
