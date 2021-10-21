cd /home/soradji/Desktop/accuknox/KubeArmor/contribution/vagrant; NETNEXT=1 DLV_RPORT=2346 vagrant up; true
Bringing machine 'kubearmor-dev-next' up with 'virtualbox' provider...
==> kubearmor-dev-next: Importing base box 'ubuntu/impish64'...
[KProgress: 90%[K==> kubearmor-dev-next: Matching MAC address for NAT networking...
==> kubearmor-dev-next: Checking if box 'ubuntu/impish64' version '20210904.0.0' is up to date...
==> kubearmor-dev-next: Setting the name of the VM: kubearmor-dev-next
==> kubearmor-dev-next: Clearing any previously set network interfaces...
==> kubearmor-dev-next: Preparing network interfaces based on configuration...
    kubearmor-dev-next: Adapter 1: nat
==> kubearmor-dev-next: Forwarding ports...
    kubearmor-dev-next: 2345 (guest) => 2346 (host) (adapter 1)
    kubearmor-dev-next: 22 (guest) => 2222 (host) (adapter 1)
==> kubearmor-dev-next: Running 'pre-boot' VM customizations...
==> kubearmor-dev-next: Booting VM...
==> kubearmor-dev-next: Waiting for machine to boot. This may take a few minutes...
    kubearmor-dev-next: SSH address: 127.0.0.1:2222
    kubearmor-dev-next: SSH username: vagrant
    kubearmor-dev-next: SSH auth method: private key
    kubearmor-dev-next: 
    kubearmor-dev-next: Vagrant insecure key detected. Vagrant will automatically replace
    kubearmor-dev-next: this with a newly generated keypair for better security.
    kubearmor-dev-next: 
    kubearmor-dev-next: Inserting generated public key within guest...
    kubearmor-dev-next: Removing insecure key from the guest if it's present...
    kubearmor-dev-next: Key inserted! Disconnecting and reconnecting using new SSH key...
==> kubearmor-dev-next: Machine booted and ready!
==> kubearmor-dev-next: Checking for guest additions in VM...
    kubearmor-dev-next: The guest additions on this VM do not match the installed version of
    kubearmor-dev-next: VirtualBox! In most cases this is fine, but in rare cases it can
    kubearmor-dev-next: prevent things such as shared folders from working properly. If you see
    kubearmor-dev-next: shared folder errors, please make sure the guest additions within the
    kubearmor-dev-next: virtual machine match the version of VirtualBox you have installed on
    kubearmor-dev-next: your host and reload your VM.
    kubearmor-dev-next: 
    kubearmor-dev-next: Guest Additions Version: 6.0.0 r127566
    kubearmor-dev-next: VirtualBox Version: 6.1
==> kubearmor-dev-next: Setting hostname...
==> kubearmor-dev-next: Mounting shared folders...
    kubearmor-dev-next: /vagrant => /home/soradji/Desktop/accuknox/KubeArmor/contribution/vagrant
    kubearmor-dev-next: /home/vagrant/KubeArmor => /home/soradji/Desktop/accuknox/KubeArmor
==> kubearmor-dev-next: Running provisioner: file...
    kubearmor-dev-next: ~/.ssh/id_rsa.pub => /home/vagrant/.ssh/id_rsa.pub
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: inline script
==> kubearmor-dev-next: Running provisioner: file...
    kubearmor-dev-next: ~/.gitconfig => $HOME/.gitconfig
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: /tmp/vagrant-shell20211020-109471-1q4y14e.sh
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish InRelease [270 kB]
    kubearmor-dev-next: Get:2 http://security.ubuntu.com/ubuntu impish-security InRelease [90.7 kB]
    kubearmor-dev-next: Get:3 http://archive.ubuntu.com/ubuntu impish-updates InRelease [90.7 kB]
    kubearmor-dev-next: Get:4 http://archive.ubuntu.com/ubuntu impish-backports InRelease [90.7 kB]
    kubearmor-dev-next: Get:5 http://archive.ubuntu.com/ubuntu impish/main amd64 Packages [1396 kB]
    kubearmor-dev-next: Get:6 http://security.ubuntu.com/ubuntu impish-security/main amd64 Packages [2672 B]
    kubearmor-dev-next: Get:7 http://security.ubuntu.com/ubuntu impish-security/main Translation-en [2508 B]
    kubearmor-dev-next: Get:8 http://security.ubuntu.com/ubuntu impish-security/universe amd64 Packages [2416 B]
    kubearmor-dev-next: Get:9 http://security.ubuntu.com/ubuntu impish-security/universe Translation-en [2080 B]
    kubearmor-dev-next: Get:10 http://security.ubuntu.com/ubuntu impish-security/universe amd64 c-n-f Metadata [116 B]
    kubearmor-dev-next: Get:11 http://security.ubuntu.com/ubuntu impish-security/multiverse amd64 c-n-f Metadata [116 B]
    kubearmor-dev-next: Get:12 http://archive.ubuntu.com/ubuntu impish/main Translation-en [511 kB]
    kubearmor-dev-next: Get:13 http://archive.ubuntu.com/ubuntu impish/restricted amd64 Packages [82.2 kB]
    kubearmor-dev-next: Get:14 http://archive.ubuntu.com/ubuntu impish/restricted Translation-en [11.9 kB]
    kubearmor-dev-next: Get:15 http://archive.ubuntu.com/ubuntu impish/universe amd64 Packages [13.1 MB]
    kubearmor-dev-next: Get:16 http://archive.ubuntu.com/ubuntu impish/universe Translation-en [5463 kB]
    kubearmor-dev-next: Get:17 http://archive.ubuntu.com/ubuntu impish/universe amd64 c-n-f Metadata [279 kB]
    kubearmor-dev-next: Get:18 http://archive.ubuntu.com/ubuntu impish/multiverse amd64 Packages [209 kB]
    kubearmor-dev-next: Get:19 http://archive.ubuntu.com/ubuntu impish/multiverse Translation-en [108 kB]
    kubearmor-dev-next: Get:20 http://archive.ubuntu.com/ubuntu impish/multiverse amd64 c-n-f Metadata [8124 B]
    kubearmor-dev-next: Get:21 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 Packages [17.8 kB]
    kubearmor-dev-next: Get:22 http://archive.ubuntu.com/ubuntu impish-updates/main Translation-en [6972 B]
    kubearmor-dev-next: Get:23 http://archive.ubuntu.com/ubuntu impish-updates/restricted amd64 Packages [18.2 kB]
    kubearmor-dev-next: Get:24 http://archive.ubuntu.com/ubuntu impish-updates/restricted Translation-en [2868 B]
    kubearmor-dev-next: Get:25 http://archive.ubuntu.com/ubuntu impish-updates/universe amd64 Packages [2416 B]
    kubearmor-dev-next: Get:26 http://archive.ubuntu.com/ubuntu impish-updates/universe Translation-en [2080 B]
    kubearmor-dev-next: Get:27 http://archive.ubuntu.com/ubuntu impish-updates/universe amd64 c-n-f Metadata [112 B]
    kubearmor-dev-next: Get:28 http://archive.ubuntu.com/ubuntu impish-updates/multiverse amd64 c-n-f Metadata [116 B]
    kubearmor-dev-next: Get:29 http://archive.ubuntu.com/ubuntu impish-backports/main amd64 c-n-f Metadata [112 B]
    kubearmor-dev-next: Get:30 http://archive.ubuntu.com/ubuntu impish-backports/restricted amd64 c-n-f Metadata [116 B]
    kubearmor-dev-next: Get:31 http://archive.ubuntu.com/ubuntu impish-backports/universe amd64 c-n-f Metadata [116 B]
    kubearmor-dev-next: Get:32 http://archive.ubuntu.com/ubuntu impish-backports/multiverse amd64 c-n-f Metadata [116 B]
    kubearmor-dev-next: Fetched 21.8 MB in 19s (1146 kB/s)
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: Calculating upgrade...
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: The following packages will be REMOVED:
    kubearmor-dev-next:   libffi8ubuntu1
    kubearmor-dev-next: The following NEW packages will be installed:
    kubearmor-dev-next:   libffi8 linux-headers-5.13.0-20 linux-headers-5.13.0-20-generic
    kubearmor-dev-next:   linux-image-5.13.0-20-generic linux-modules-5.13.0-20-generic
    kubearmor-dev-next: The following packages will be upgraded:
    kubearmor-dev-next:   accountsservice apport apt apt-utils base-files bash bc bcache-tools
    kubearmor-dev-next:   binutils binutils-common binutils-x86-64-linux-gnu bolt btrfs-progs
    kubearmor-dev-next:   busybox-initramfs busybox-static ca-certificates cloud-init
    kubearmor-dev-next:   command-not-found cryptsetup cryptsetup-bin cryptsetup-initramfs
    kubearmor-dev-next:   cryptsetup-run curl dash dbus distro-info-data dmeventd dmsetup dosfstools
    kubearmor-dev-next:   e2fsprogs eatmydata ethtool gcc-11-base gir1.2-glib-2.0
    kubearmor-dev-next:   gir1.2-packagekitglib-1.0 grep groff-base grub-common grub-pc grub-pc-bin
    kubearmor-dev-next:   grub2-common hdparm hostname htop init init-system-helpers irqbalance kbd
    kubearmor-dev-next:   landscape-common language-selector-common libaccountsservice0 libacl1
    kubearmor-dev-next:   libappstream4 libapt-pkg6.0 libatm1 libattr1 libbinutils libblockdev-crypto2
    kubearmor-dev-next:   libblockdev-fs2 libblockdev-loop2 libblockdev-part-err2 libblockdev-part2
    kubearmor-dev-next:   libblockdev-swap2 libblockdev-utils2 libblockdev2 libbrotli1 libc-bin libc6
    kubearmor-dev-next:   libcom-err2 libcryptsetup12 libctf-nobfd0 libctf0 libcurl3-gnutls libcurl4
    kubearmor-dev-next:   libdbus-1-3 libdevmapper-event1.02.1 libdevmapper1.02.1 libdrm-common
    kubearmor-dev-next:   libdrm2 libdw1 libeatmydata1 libedit2 libefiboot1 libefivar1 libelf1
    kubearmor-dev-next:   libestr0 libexpat1 libext2fs2 libfastjson4 libfido2-1 libfribidi0
    kubearmor-dev-next:   libgcab-1.0-0 libgcc-s1 libgcrypt20 libgirepository-1.0-1 libglib2.0-0
    kubearmor-dev-next:   libglib2.0-bin libglib2.0-data libgpm2 libgstreamer1.0-0 libgusb2 libjcat1
    kubearmor-dev-next:   liblvm2cmd2.03 libmpdec3 libmspack0 libnetplan0 libnewt0.52 libnsl2
    kubearmor-dev-next:   libnss-systemd libntfs-3g883 libp11-kit0 libpackagekit-glib2-18
    kubearmor-dev-next:   libpam-modules libpam-modules-bin libpam-runtime libpam-systemd libpam0g
    kubearmor-dev-next:   libpcap0.8 libpipeline1 libplymouth5 libpng16-16 libproc-processtable-perl
    kubearmor-dev-next:   libpython3-stdlib libpython3.9 libpython3.9-minimal libpython3.9-stdlib
    kubearmor-dev-next:   librtmp1 libselinux1 libsemanage-common libsemanage1 libsepol1 libsigsegv2
    kubearmor-dev-next:   libsmbios-c2 libss2 libssl1.1 libstdc++6 libsystemd0 libtirpc-common
    kubearmor-dev-next:   libtirpc3 libuchardet0 libudev1 libudisks2-0 libunistring2 libuv1
    kubearmor-dev-next:   libvolume-key1 libxdmcp6 libxml2 libxmlsec1 libxmlsec1-openssl libxxhash0
    kubearmor-dev-next:   linux-headers-generic linux-headers-virtual linux-image-virtual
    kubearmor-dev-next:   linux-virtual locales logsave lsb-base lsb-release ltrace lvm2
    kubearmor-dev-next:   motd-news-config mtr-tiny netplan.io ntfs-3g open-vm-tools openssh-client
    kubearmor-dev-next:   openssh-server openssh-sftp-server openssl packagekit packagekit-tools
    kubearmor-dev-next:   plymouth plymouth-theme-ubuntu-text python3 python3-apport
    kubearmor-dev-next:   python3-cffi-backend python3-commandnotfound python3-debian
    kubearmor-dev-next:   python3-distupgrade python3-distutils python3-gdbm python3-gi
    kubearmor-dev-next:   python3-lib2to3 python3-minimal python3-newt python3-problem-report
    kubearmor-dev-next:   python3.9 python3.9-minimal rsyslog snapd squashfs-tools systemd
    kubearmor-dev-next:   systemd-sysv systemd-timesyncd tmux tzdata ubuntu-minimal
    kubearmor-dev-next:   ubuntu-release-upgrader-core ubuntu-server ubuntu-standard udev udisks2 ufw
    kubearmor-dev-next:   usbutils vim vim-common vim-runtime vim-tiny whiptail xdg-user-dirs xfsprogs
    kubearmor-dev-next:   xxd zerofree
    kubearmor-dev-next: 213 upgraded, 5 newly installed, 1 to remove and 0 not upgraded.
    kubearmor-dev-next: 1 standard security update
    kubearmor-dev-next: Need to get 138 MB of archives.
    kubearmor-dev-next: After this operation, 205 MB of additional disk space will be used.
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish/main amd64 motd-news-config all 11.1ubuntu5 [4896 B]
    kubearmor-dev-next: Get:2 http://archive.ubuntu.com/ubuntu impish/main amd64 btrfs-progs amd64 5.10.1-2build1 [775 kB]
    kubearmor-dev-next: Get:3 http://archive.ubuntu.com/ubuntu impish/main amd64 gcc-11-base amd64 11.2.0-7ubuntu2 [20.5 kB]
    kubearmor-dev-next: Get:4 http://archive.ubuntu.com/ubuntu impish/main amd64 libgcc-s1 amd64 11.2.0-7ubuntu2 [45.6 kB]
    kubearmor-dev-next: Get:5 http://archive.ubuntu.com/ubuntu impish/main amd64 libstdc++6 amd64 11.2.0-7ubuntu2 [656 kB]
    kubearmor-dev-next: Get:6 http://archive.ubuntu.com/ubuntu impish/main amd64 libcom-err2 amd64 1.46.3-1ubuntu3 [10.7 kB]
    kubearmor-dev-next: Get:7 http://archive.ubuntu.com/ubuntu impish/main amd64 logsave amd64 1.46.3-1ubuntu3 [11.5 kB]
    kubearmor-dev-next: Get:8 http://archive.ubuntu.com/ubuntu impish/main amd64 libext2fs2 amd64 1.46.3-1ubuntu3 [210 kB]
    kubearmor-dev-next: Get:9 http://archive.ubuntu.com/ubuntu impish/main amd64 e2fsprogs amd64 1.46.3-1ubuntu3 [588 kB]
    kubearmor-dev-next: Get:10 http://archive.ubuntu.com/ubuntu impish/main amd64 libc6 amd64 2.34-0ubuntu3 [3028 kB]
    kubearmor-dev-next: Get:11 http://archive.ubuntu.com/ubuntu impish/main amd64 base-files amd64 11.1ubuntu5 [63.1 kB]
    kubearmor-dev-next: Get:12 http://archive.ubuntu.com/ubuntu impish/main amd64 bash amd64 5.1-3ubuntu2 [775 kB]
    kubearmor-dev-next: Get:13 http://archive.ubuntu.com/ubuntu impish/main amd64 dash amd64 0.5.11+git20210120+802ebd4-1build1 [92.4 kB]
    kubearmor-dev-next: Get:14 http://archive.ubuntu.com/ubuntu impish/main amd64 grep amd64 3.7-0ubuntu1 [195 kB]
    kubearmor-dev-next: Get:15 http://archive.ubuntu.com/ubuntu impish/main amd64 hostname amd64 3.23ubuntu1 [11.5 kB]
    kubearmor-dev-next: Get:16 http://archive.ubuntu.com/ubuntu impish/main amd64 init-system-helpers all 1.60build1 [38.6 kB]
    kubearmor-dev-next: Get:17 http://archive.ubuntu.com/ubuntu impish/main amd64 libc-bin amd64 2.34-0ubuntu3 [1023 kB]
    kubearmor-dev-next: Get:18 http://archive.ubuntu.com/ubuntu impish/main amd64 libgcrypt20 amd64 1.8.7-5ubuntu2 [468 kB]
    kubearmor-dev-next: Get:19 http://archive.ubuntu.com/ubuntu impish/main amd64 libnss-systemd amd64 248.3-1ubuntu8 [126 kB]
    kubearmor-dev-next: Get:20 http://archive.ubuntu.com/ubuntu impish/main amd64 libsystemd0 amd64 248.3-1ubuntu8 [307 kB]
    kubearmor-dev-next: Get:21 http://archive.ubuntu.com/ubuntu impish/main amd64 systemd-timesyncd amd64 248.3-1ubuntu8 [30.8 kB]
    kubearmor-dev-next: Get:22 http://archive.ubuntu.com/ubuntu impish/main amd64 systemd-sysv amd64 248.3-1ubuntu8 [10.5 kB]
    kubearmor-dev-next: Get:23 http://archive.ubuntu.com/ubuntu impish/main amd64 libpam-systemd amd64 248.3-1ubuntu8 [199 kB]
    kubearmor-dev-next: Get:24 http://archive.ubuntu.com/ubuntu impish/main amd64 systemd amd64 248.3-1ubuntu8 [4402 kB]
    kubearmor-dev-next: Get:25 http://archive.ubuntu.com/ubuntu impish/main amd64 udev amd64 248.3-1ubuntu8 [1518 kB]
    kubearmor-dev-next: Get:26 http://archive.ubuntu.com/ubuntu impish/main amd64 libudev1 amd64 248.3-1ubuntu8 [76.2 kB]
    kubearmor-dev-next: Get:27 http://archive.ubuntu.com/ubuntu impish/main amd64 libacl1 amd64 2.2.53-10ubuntu2 [16.1 kB]
    kubearmor-dev-next: Get:28 http://archive.ubuntu.com/ubuntu impish/main amd64 libselinux1 amd64 3.1-3build2 [74.4 kB]
    kubearmor-dev-next: Get:29 http://archive.ubuntu.com/ubuntu impish/main amd64 libpam0g amd64 1.3.1-5ubuntu11 [58.4 kB]
    kubearmor-dev-next: Get:30 http://archive.ubuntu.com/ubuntu impish/main amd64 libpam-modules-bin amd64 1.3.1-5ubuntu11 [41.2 kB]
    kubearmor-dev-next: Get:31 http://archive.ubuntu.com/ubuntu impish/main amd64 libpam-modules amd64 1.3.1-5ubuntu11 [272 kB]
    kubearmor-dev-next: Get:32 http://archive.ubuntu.com/ubuntu impish/main amd64 libpam-runtime all 1.3.1-5ubuntu11 [38.7 kB]
    kubearmor-dev-next: Get:33 http://archive.ubuntu.com/ubuntu impish/main amd64 dbus amd64 1.12.20-2ubuntu2 [158 kB]
    kubearmor-dev-next: Get:34 http://archive.ubuntu.com/ubuntu impish/main amd64 libdbus-1-3 amd64 1.12.20-2ubuntu2 [189 kB]
    kubearmor-dev-next: Get:35 http://archive.ubuntu.com/ubuntu impish/main amd64 libexpat1 amd64 2.4.1-2 [90.1 kB]
    kubearmor-dev-next: Get:36 http://archive.ubuntu.com/ubuntu impish/main amd64 libdevmapper1.02.1 amd64 2:1.02.175-2.1ubuntu3 [139 kB]
    kubearmor-dev-next: Get:37 http://archive.ubuntu.com/ubuntu impish/main amd64 libssl1.1 amd64 1.1.1l-1ubuntu1 [1446 kB]
    kubearmor-dev-next: Get:38 http://archive.ubuntu.com/ubuntu impish/main amd64 libcryptsetup12 amd64 2:2.3.6-0ubuntu1 [213 kB]
    kubearmor-dev-next: Get:39 http://archive.ubuntu.com/ubuntu impish/main amd64 libxxhash0 amd64 0.8.0-2build1 [26.4 kB]
    kubearmor-dev-next: Get:40 http://archive.ubuntu.com/ubuntu impish/main amd64 libapt-pkg6.0 amd64 2.3.9 [900 kB]
    kubearmor-dev-next: Get:41 http://archive.ubuntu.com/ubuntu impish/main amd64 apt amd64 2.3.9 [1382 kB]
    kubearmor-dev-next: Get:42 http://archive.ubuntu.com/ubuntu impish/main amd64 apt-utils amd64 2.3.9 [211 kB]
    kubearmor-dev-next: Get:43 http://archive.ubuntu.com/ubuntu impish/main amd64 libglib2.0-bin amd64 2.68.4-1ubuntu1 [80.5 kB]
    kubearmor-dev-next: Get:44 http://archive.ubuntu.com/ubuntu impish/main amd64 libglib2.0-0 amd64 2.68.4-1ubuntu1 [1424 kB]
    kubearmor-dev-next: Get:45 http://archive.ubuntu.com/ubuntu impish/main amd64 libgirepository-1.0-1 amd64 1.68.0-1build2 [54.9 kB]
    kubearmor-dev-next: Get:46 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-gi amd64 3.40.1-1build1 [229 kB]
    kubearmor-dev-next: Get:47 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-cffi-backend amd64 1.14.6-1build1 [77.3 kB]
    kubearmor-dev-next: Get:48 http://archive.ubuntu.com/ubuntu impish/main amd64 python3.9 amd64 3.9.7-2build1 [433 kB]
    kubearmor-dev-next: Get:49 http://archive.ubuntu.com/ubuntu impish/main amd64 python3.9-minimal amd64 3.9.7-2build1 [2081 kB]
    kubearmor-dev-next: Get:50 http://archive.ubuntu.com/ubuntu impish/main amd64 libpython3.9-minimal amd64 3.9.7-2build1 [784 kB]
    kubearmor-dev-next: Get:51 http://archive.ubuntu.com/ubuntu impish/main amd64 libpython3.9 amd64 3.9.7-2build1 [1897 kB]
    kubearmor-dev-next: Get:52 http://archive.ubuntu.com/ubuntu impish/main amd64 libpython3.9-stdlib amd64 3.9.7-2build1 [1807 kB]
    kubearmor-dev-next: Get:53 http://archive.ubuntu.com/ubuntu impish/main amd64 libffi8 amd64 3.4.2-1ubuntu5 [21.8 kB]
    kubearmor-dev-next: Get:54 http://archive.ubuntu.com/ubuntu impish/main amd64 libp11-kit0 amd64 0.23.22-1build1 [254 kB]
    kubearmor-dev-next: Get:55 http://archive.ubuntu.com/ubuntu impish/main amd64 init amd64 1.60build1 [5912 B]
    kubearmor-dev-next: Get:56 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-minimal amd64 3.9.4-1build1 [24.5 kB]
    kubearmor-dev-next: Get:57 http://archive.ubuntu.com/ubuntu impish/main amd64 python3 amd64 3.9.4-1build1 [22.8 kB]
    kubearmor-dev-next: Get:58 http://archive.ubuntu.com/ubuntu impish/main amd64 tzdata all 2021a-2ubuntu1 [339 kB]
    kubearmor-dev-next: Get:59 http://archive.ubuntu.com/ubuntu impish/main amd64 libmpdec3 amd64 2.5.1-2build1 [86.8 kB]
    kubearmor-dev-next: Get:60 http://archive.ubuntu.com/ubuntu impish/main amd64 libtirpc-common all 1.3.2-2 [7674 B]
    kubearmor-dev-next: Get:61 http://archive.ubuntu.com/ubuntu impish/main amd64 libtirpc3 amd64 1.3.2-2 [81.5 kB]
    kubearmor-dev-next: Get:62 http://archive.ubuntu.com/ubuntu impish/main amd64 libnsl2 amd64 1.3.0-2build1 [42.3 kB]
    kubearmor-dev-next: Get:63 http://archive.ubuntu.com/ubuntu impish/main amd64 libpython3-stdlib amd64 3.9.4-1build1 [7146 B]
    kubearmor-dev-next: Get:64 http://archive.ubuntu.com/ubuntu impish/main amd64 libestr0 amd64 0.1.10-2.1build2 [7756 B]
    kubearmor-dev-next: Get:65 http://archive.ubuntu.com/ubuntu impish/main amd64 libfastjson4 amd64 0.99.9-1build1 [22.9 kB]
    kubearmor-dev-next: Get:66 http://archive.ubuntu.com/ubuntu impish/main amd64 rsyslog amd64 8.2102.0-2ubuntu2 [487 kB]
    kubearmor-dev-next: Get:67 http://archive.ubuntu.com/ubuntu impish/main amd64 libglib2.0-data all 2.68.4-1ubuntu1 [6230 B]
    kubearmor-dev-next: Get:68 http://archive.ubuntu.com/ubuntu impish/main amd64 libdw1 amd64 0.185-1build1 [249 kB]
    kubearmor-dev-next: Get:69 http://archive.ubuntu.com/ubuntu impish/main amd64 libelf1 amd64 0.185-1build1 [51.4 kB]
    kubearmor-dev-next: Get:70 http://archive.ubuntu.com/ubuntu impish/main amd64 irqbalance amd64 1.7.0-1build1 [45.6 kB]
    kubearmor-dev-next: Get:71 http://archive.ubuntu.com/ubuntu impish/main amd64 ntfs-3g amd64 1:2017.3.23AR.3-3ubuntu5 [405 kB]
    kubearmor-dev-next: Get:72 http://archive.ubuntu.com/ubuntu impish/main amd64 libntfs-3g883 amd64 1:2017.3.23AR.3-3ubuntu5 [159 kB]
    kubearmor-dev-next: Get:73 http://archive.ubuntu.com/ubuntu impish/main amd64 accountsservice amd64 0.6.55-0ubuntu14 [60.1 kB]
    kubearmor-dev-next: Get:74 http://archive.ubuntu.com/ubuntu impish/main amd64 libaccountsservice0 amd64 0.6.55-0ubuntu14 [82.9 kB]
    kubearmor-dev-next: Get:75 http://archive.ubuntu.com/ubuntu impish/main amd64 language-selector-common all 0.216 [246 kB]
    kubearmor-dev-next: Get:76 http://archive.ubuntu.com/ubuntu impish/main amd64 libdevmapper-event1.02.1 amd64 2:1.02.175-2.1ubuntu3 [12.6 kB]
    kubearmor-dev-next: Get:77 http://archive.ubuntu.com/ubuntu impish/main amd64 libedit2 amd64 3.1-20191231-2build1 [97.4 kB]
    kubearmor-dev-next: Get:78 http://archive.ubuntu.com/ubuntu impish/main amd64 lsb-base all 11.1.0ubuntu3 [12.3 kB]
    kubearmor-dev-next: Get:79 http://archive.ubuntu.com/ubuntu impish/main amd64 dmsetup amd64 2:1.02.175-2.1ubuntu3 [81.6 kB]
    kubearmor-dev-next: Get:80 http://archive.ubuntu.com/ubuntu impish/main amd64 liblvm2cmd2.03 amd64 2.03.11-2.1ubuntu3 [757 kB]
    kubearmor-dev-next: Get:81 http://archive.ubuntu.com/ubuntu impish/main amd64 dmeventd amd64 2:1.02.175-2.1ubuntu3 [38.1 kB]
    kubearmor-dev-next: Get:82 http://archive.ubuntu.com/ubuntu impish/main amd64 lvm2 amd64 2.03.11-2.1ubuntu3 [1154 kB]
    kubearmor-dev-next: Get:83 http://archive.ubuntu.com/ubuntu impish/main amd64 libdrm-common all 2.4.107-8ubuntu1 [5490 B]
    kubearmor-dev-next: Get:84 http://archive.ubuntu.com/ubuntu impish/main amd64 libdrm2 amd64 2.4.107-8ubuntu1 [37.0 kB]
    kubearmor-dev-next: Get:85 http://archive.ubuntu.com/ubuntu impish/main amd64 libmspack0 amd64 0.10.1-2build1 [39.6 kB]
    kubearmor-dev-next: Get:86 http://archive.ubuntu.com/ubuntu impish/main amd64 libxml2 amd64 2.9.12+dfsg-4 [761 kB]
    kubearmor-dev-next: Get:87 http://archive.ubuntu.com/ubuntu impish/main amd64 libxmlsec1 amd64 1.2.32-1build1 [139 kB]
    kubearmor-dev-next: Get:88 http://archive.ubuntu.com/ubuntu impish/main amd64 libxmlsec1-openssl amd64 1.2.32-1build1 [84.4 kB]
    kubearmor-dev-next: Get:89 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 distro-info-data all 0.51ubuntu1.1 [5112 B]
    kubearmor-dev-next: Get:90 http://archive.ubuntu.com/ubuntu impish/main amd64 lsb-release all 11.1.0ubuntu3 [10.8 kB]
    kubearmor-dev-next: Get:91 http://archive.ubuntu.com/ubuntu impish/main amd64 open-vm-tools amd64 2:11.3.0-2ubuntu1 [718 kB]
    kubearmor-dev-next: Get:92 http://archive.ubuntu.com/ubuntu impish/main amd64 libattr1 amd64 1:2.4.48-6build2 [13.2 kB]
    kubearmor-dev-next: Get:93 http://archive.ubuntu.com/ubuntu impish/main amd64 libsepol1 amd64 3.1-1ubuntu2 [280 kB]
    kubearmor-dev-next: Get:94 http://archive.ubuntu.com/ubuntu impish/main amd64 libsemanage-common all 3.1-1ubuntu2 [9638 B]
    kubearmor-dev-next: Get:95 http://archive.ubuntu.com/ubuntu impish/main amd64 libsemanage1 amd64 3.1-1ubuntu2 [96.5 kB]
    kubearmor-dev-next: Get:96 http://archive.ubuntu.com/ubuntu impish/main amd64 libunistring2 amd64 0.9.10-6 [503 kB]
    kubearmor-dev-next: Get:97 http://archive.ubuntu.com/ubuntu impish/main amd64 libss2 amd64 1.46.3-1ubuntu3 [12.3 kB]
    kubearmor-dev-next: Get:98 http://archive.ubuntu.com/ubuntu impish/main amd64 openssl amd64 1.1.1l-1ubuntu1 [651 kB]
    kubearmor-dev-next: Get:99 http://archive.ubuntu.com/ubuntu impish/main amd64 ca-certificates all 20210119ubuntu1 [149 kB]
    kubearmor-dev-next: Get:100 http://archive.ubuntu.com/ubuntu impish/main amd64 gir1.2-glib-2.0 amd64 1.68.0-1build2 [161 kB]
    kubearmor-dev-next: Get:101 http://archive.ubuntu.com/ubuntu impish/main amd64 kbd amd64 2.3.0-3ubuntu3 [246 kB]
    kubearmor-dev-next: Get:102 http://archive.ubuntu.com/ubuntu impish/main amd64 libatm1 amd64 1:2.5.1-4build1 [23.0 kB]
    kubearmor-dev-next: Get:103 http://archive.ubuntu.com/ubuntu impish/main amd64 libfribidi0 amd64 1.0.8-2ubuntu2 [25.7 kB]
    kubearmor-dev-next: Get:104 http://archive.ubuntu.com/ubuntu impish/main amd64 libnetplan0 amd64 0.103-0ubuntu7 [57.9 kB]
    kubearmor-dev-next: Get:105 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-newt amd64 0.52.21-4ubuntu7 [21.4 kB]
    kubearmor-dev-next: Get:106 http://archive.ubuntu.com/ubuntu impish/main amd64 libnewt0.52 amd64 0.52.21-4ubuntu7 [45.8 kB]
    kubearmor-dev-next: Get:107 http://archive.ubuntu.com/ubuntu impish/main amd64 locales all 2.34-0ubuntu3 [4235 kB]
    kubearmor-dev-next: Get:108 http://archive.ubuntu.com/ubuntu impish/main amd64 netplan.io amd64 0.103-0ubuntu7 [103 kB]
    kubearmor-dev-next: Get:109 http://archive.ubuntu.com/ubuntu impish/main amd64 xxd amd64 2:8.2.2434-3ubuntu3 [50.6 kB]
    kubearmor-dev-next: Get:110 http://archive.ubuntu.com/ubuntu impish/main amd64 vim amd64 2:8.2.2434-3ubuntu3 [1614 kB]
    kubearmor-dev-next: Get:111 http://archive.ubuntu.com/ubuntu impish/main amd64 vim-tiny amd64 2:8.2.2434-3ubuntu3 [674 kB]
    kubearmor-dev-next: Get:112 http://archive.ubuntu.com/ubuntu impish/main amd64 vim-runtime all 2:8.2.2434-3ubuntu3 [6702 kB]
    kubearmor-dev-next: Get:113 http://archive.ubuntu.com/ubuntu impish/main amd64 vim-common all 2:8.2.2434-3ubuntu3 [81.3 kB]
    kubearmor-dev-next: Get:114 http://archive.ubuntu.com/ubuntu impish/main amd64 libgpm2 amd64 1.20.7-8build1 [15.9 kB]
    kubearmor-dev-next: Get:115 http://archive.ubuntu.com/ubuntu impish/main amd64 whiptail amd64 0.52.21-4ubuntu7 [17.3 kB]
    kubearmor-dev-next: Get:116 http://archive.ubuntu.com/ubuntu impish/main amd64 ubuntu-minimal amd64 1.472 [2856 B]
    kubearmor-dev-next: Get:117 http://archive.ubuntu.com/ubuntu impish/main amd64 xdg-user-dirs amd64 0.17-2ubuntu3 [53.8 kB]
    kubearmor-dev-next: Get:118 http://archive.ubuntu.com/ubuntu impish/main amd64 busybox-static amd64 1:1.30.1-6ubuntu3 [1014 kB]
    kubearmor-dev-next: Get:119 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-gdbm amd64 3.9.7-1 [21.9 kB]
    kubearmor-dev-next: Get:120 http://archive.ubuntu.com/ubuntu impish/main amd64 command-not-found all 21.10.0 [5078 B]
    kubearmor-dev-next: Get:121 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-commandnotfound all 21.10.0 [10.3 kB]
    kubearmor-dev-next: Get:122 http://archive.ubuntu.com/ubuntu impish/main amd64 dosfstools amd64 4.2-1build2 [88.3 kB]
    kubearmor-dev-next: Get:123 http://archive.ubuntu.com/ubuntu impish/main amd64 libuchardet0 amd64 0.0.7-1build1 [76.7 kB]
    kubearmor-dev-next: Get:124 http://archive.ubuntu.com/ubuntu impish/main amd64 groff-base amd64 1.22.4-7 [956 kB]
    kubearmor-dev-next: Get:125 http://archive.ubuntu.com/ubuntu impish/main amd64 hdparm amd64 9.60+ds-1build2 [98.8 kB]
    kubearmor-dev-next: Get:126 http://archive.ubuntu.com/ubuntu impish/main amd64 libfido2-1 amd64 1.6.0-2build1 [58.1 kB]
    kubearmor-dev-next: Get:127 http://archive.ubuntu.com/ubuntu impish/main amd64 libpcap0.8 amd64 1.10.0-2build1 [148 kB]
    kubearmor-dev-next: Get:128 http://archive.ubuntu.com/ubuntu impish/main amd64 libpipeline1 amd64 1.5.3-1build1 [23.2 kB]
    kubearmor-dev-next: Get:129 http://archive.ubuntu.com/ubuntu impish/main amd64 libpng16-16 amd64 1.6.37-3build4 [191 kB]
    kubearmor-dev-next: Get:130 http://archive.ubuntu.com/ubuntu impish/main amd64 libplymouth5 amd64 0.9.5git20210406-0ubuntu2 [107 kB]
    kubearmor-dev-next: Get:131 http://archive.ubuntu.com/ubuntu impish/main amd64 libuv1 amd64 1.40.0-2ubuntu1 [90.9 kB]
    kubearmor-dev-next: Get:132 http://archive.ubuntu.com/ubuntu impish/main amd64 libxdmcp6 amd64 1:1.1.3-0ubuntu4 [11.0 kB]
    kubearmor-dev-next: Get:133 http://archive.ubuntu.com/ubuntu impish/main amd64 ltrace amd64 0.7.3-6.1ubuntu3 [141 kB]
    kubearmor-dev-next: Get:134 http://archive.ubuntu.com/ubuntu impish/main amd64 mtr-tiny amd64 0.94-1build1 [54.4 kB]
    kubearmor-dev-next: Get:135 http://archive.ubuntu.com/ubuntu impish/main amd64 openssh-sftp-server amd64 1:8.4p1-6ubuntu2 [32.9 kB]
    kubearmor-dev-next: Get:136 http://archive.ubuntu.com/ubuntu impish/main amd64 openssh-server amd64 1:8.4p1-6ubuntu2 [382 kB]
    kubearmor-dev-next: Get:137 http://archive.ubuntu.com/ubuntu impish/main amd64 openssh-client amd64 1:8.4p1-6ubuntu2 [771 kB]
    kubearmor-dev-next: Get:138 http://archive.ubuntu.com/ubuntu impish/main amd64 plymouth-theme-ubuntu-text amd64 0.9.5git20210406-0ubuntu2 [10.1 kB]
    kubearmor-dev-next: Get:139 http://archive.ubuntu.com/ubuntu impish/main amd64 libpackagekit-glib2-18 amd64 1.2.2-2ubuntu3 [123 kB]
    kubearmor-dev-next: Get:140 http://archive.ubuntu.com/ubuntu impish/main amd64 packagekit-tools amd64 1.2.2-2ubuntu3 [28.6 kB]
    kubearmor-dev-next: Get:141 http://archive.ubuntu.com/ubuntu impish/main amd64 libbrotli1 amd64 1.0.9-2build3 [315 kB]
    kubearmor-dev-next: Get:142 http://archive.ubuntu.com/ubuntu impish/main amd64 librtmp1 amd64 2.4+20151223.gitfa8646d.1-2build3 [58.3 kB]
    kubearmor-dev-next: Get:143 http://archive.ubuntu.com/ubuntu impish/main amd64 libcurl3-gnutls amd64 7.74.0-1.3ubuntu2 [268 kB]
    kubearmor-dev-next: Get:144 http://archive.ubuntu.com/ubuntu impish/main amd64 libappstream4 amd64 0.14.5-1 [183 kB]
    kubearmor-dev-next: Get:145 http://archive.ubuntu.com/ubuntu impish/main amd64 libgstreamer1.0-0 amd64 1.18.5-1 [971 kB]
    kubearmor-dev-next: Get:146 http://archive.ubuntu.com/ubuntu impish/main amd64 packagekit amd64 1.2.2-2ubuntu3 [436 kB]
    kubearmor-dev-next: Get:147 http://archive.ubuntu.com/ubuntu impish/main amd64 plymouth amd64 0.9.5git20210406-0ubuntu2 [131 kB]
    kubearmor-dev-next: Get:148 http://archive.ubuntu.com/ubuntu impish/main amd64 ubuntu-release-upgrader-core all 1:21.10.8 [24.7 kB]
    kubearmor-dev-next: Get:149 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-distupgrade all 1:21.10.8 [104 kB]
    kubearmor-dev-next: Get:150 http://archive.ubuntu.com/ubuntu impish/main amd64 usbutils amd64 1:013-3build1 [85.5 kB]
    kubearmor-dev-next: Get:151 http://archive.ubuntu.com/ubuntu impish/main amd64 ubuntu-standard amd64 1.472 [2880 B]
    kubearmor-dev-next: Get:152 http://archive.ubuntu.com/ubuntu impish/main amd64 ufw all 0.36.1-1 [162 kB]
    kubearmor-dev-next: Get:153 http://archive.ubuntu.com/ubuntu impish/main amd64 libefivar1 amd64 37-6ubuntu2 [51.0 kB]
    kubearmor-dev-next: Get:154 http://archive.ubuntu.com/ubuntu impish/main amd64 libefiboot1 amd64 37-6ubuntu2 [42.8 kB]
    kubearmor-dev-next: Get:155 http://archive.ubuntu.com/ubuntu impish/main amd64 grub-pc amd64 2.04-1ubuntu47 [132 kB]
    kubearmor-dev-next: Get:156 http://archive.ubuntu.com/ubuntu impish/main amd64 grub2-common amd64 2.04-1ubuntu47 [633 kB]
    kubearmor-dev-next: Get:157 http://archive.ubuntu.com/ubuntu impish/main amd64 grub-pc-bin amd64 2.04-1ubuntu47 [1066 kB]
    kubearmor-dev-next: Get:158 http://archive.ubuntu.com/ubuntu impish/main amd64 grub-common amd64 2.04-1ubuntu47 [2155 kB]
    kubearmor-dev-next: Get:159 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-problem-report all 2.20.11-0ubuntu70 [9820 B]
    kubearmor-dev-next: Get:160 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-apport all 2.20.11-0ubuntu70 [86.7 kB]
    kubearmor-dev-next: Get:161 http://archive.ubuntu.com/ubuntu impish/main amd64 apport all 2.20.11-0ubuntu70 [131 kB]
    kubearmor-dev-next: Get:162 http://archive.ubuntu.com/ubuntu impish/main amd64 bc amd64 1.07.1-2build3 [87.8 kB]
    kubearmor-dev-next: Get:163 http://archive.ubuntu.com/ubuntu impish/main amd64 bcache-tools amd64 1.0.8-4ubuntu2 [20.3 kB]
    kubearmor-dev-next: Get:164 http://archive.ubuntu.com/ubuntu impish/main amd64 libctf0 amd64 2.37-7ubuntu1 [103 kB]
    kubearmor-dev-next: Get:165 http://archive.ubuntu.com/ubuntu impish/main amd64 libctf-nobfd0 amd64 2.37-7ubuntu1 [106 kB]
    kubearmor-dev-next: Get:166 http://archive.ubuntu.com/ubuntu impish/main amd64 binutils-x86-64-linux-gnu amd64 2.37-7ubuntu1 [2315 kB]
    kubearmor-dev-next: Get:167 http://archive.ubuntu.com/ubuntu impish/main amd64 libbinutils amd64 2.37-7ubuntu1 [654 kB]
    kubearmor-dev-next: Get:168 http://archive.ubuntu.com/ubuntu impish/main amd64 binutils amd64 2.37-7ubuntu1 [3190 B]
    kubearmor-dev-next: Get:169 http://archive.ubuntu.com/ubuntu impish/main amd64 binutils-common amd64 2.37-7ubuntu1 [212 kB]
    kubearmor-dev-next: Get:170 http://archive.ubuntu.com/ubuntu impish/main amd64 bolt amd64 0.9.1-2 [150 kB]
    kubearmor-dev-next: Get:171 http://archive.ubuntu.com/ubuntu impish/main amd64 busybox-initramfs amd64 1:1.30.1-6ubuntu3 [176 kB]
    kubearmor-dev-next: Get:172 http://archive.ubuntu.com/ubuntu impish/main amd64 cryptsetup-initramfs all 2:2.3.6-0ubuntu1 [25.4 kB]
    kubearmor-dev-next: Get:173 http://archive.ubuntu.com/ubuntu impish/main amd64 cryptsetup-bin amd64 2:2.3.6-0ubuntu1 [128 kB]
    kubearmor-dev-next: Get:174 http://archive.ubuntu.com/ubuntu impish/main amd64 cryptsetup amd64 2:2.3.6-0ubuntu1 [178 kB]
    kubearmor-dev-next: Get:175 http://archive.ubuntu.com/ubuntu impish/main amd64 cryptsetup-run all 2:2.3.6-0ubuntu1 [6490 B]
    kubearmor-dev-next: Get:176 http://archive.ubuntu.com/ubuntu impish/main amd64 curl amd64 7.74.0-1.3ubuntu2 [179 kB]
    kubearmor-dev-next: Get:177 http://archive.ubuntu.com/ubuntu impish/main amd64 libcurl4 amd64 7.74.0-1.3ubuntu2 [273 kB]
    kubearmor-dev-next: Get:178 http://archive.ubuntu.com/ubuntu impish/main amd64 libeatmydata1 amd64 105-9build2 [7856 B]
    kubearmor-dev-next: Get:179 http://archive.ubuntu.com/ubuntu impish/main amd64 eatmydata all 105-9build2 [5492 B]
    kubearmor-dev-next: Get:180 http://archive.ubuntu.com/ubuntu impish/main amd64 ethtool amd64 1:5.9-1build1 [195 kB]
    kubearmor-dev-next: Get:181 http://archive.ubuntu.com/ubuntu impish/main amd64 gir1.2-packagekitglib-1.0 amd64 1.2.2-2ubuntu3 [24.6 kB]
    kubearmor-dev-next: Get:182 http://archive.ubuntu.com/ubuntu impish/main amd64 htop amd64 3.0.5-7build1 [129 kB]
    kubearmor-dev-next: Get:183 http://archive.ubuntu.com/ubuntu impish/main amd64 landscape-common amd64 19.12-0ubuntu10 [85.8 kB]
    kubearmor-dev-next: Get:184 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev-utils2 amd64 2.25-2build1 [16.4 kB]
    kubearmor-dev-next: Get:185 http://archive.ubuntu.com/ubuntu impish/main amd64 libvolume-key1 amd64 0.3.12-3.1build2 [41.7 kB]
    kubearmor-dev-next: Get:186 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev-crypto2 amd64 2.25-2build1 [18.1 kB]
    kubearmor-dev-next: Get:187 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev-part-err2 amd64 2.25-2build1 [5666 B]
    kubearmor-dev-next: Get:188 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev-fs2 amd64 2.25-2build1 [21.7 kB]
    kubearmor-dev-next: Get:189 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev-loop2 amd64 2.25-2build1 [6902 B]
    kubearmor-dev-next: Get:190 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev-part2 amd64 2.25-2build1 [15.7 kB]
    kubearmor-dev-next: Get:191 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev-swap2 amd64 2.25-2build1 [7486 B]
    kubearmor-dev-next: Get:192 http://archive.ubuntu.com/ubuntu impish/main amd64 libblockdev2 amd64 2.25-2build1 [42.7 kB]
    kubearmor-dev-next: Get:193 http://archive.ubuntu.com/ubuntu impish/main amd64 libgcab-1.0-0 amd64 1.4-3build1 [28.9 kB]
    kubearmor-dev-next: Get:194 http://archive.ubuntu.com/ubuntu impish/main amd64 libjcat1 amd64 0.1.3-2build1 [28.4 kB]
    kubearmor-dev-next: Get:195 http://archive.ubuntu.com/ubuntu impish/main amd64 libproc-processtable-perl amd64 0.59-2build2 [36.9 kB]
    kubearmor-dev-next: Get:196 http://archive.ubuntu.com/ubuntu impish/main amd64 libsigsegv2 amd64 2.13-1ubuntu2 [14.6 kB]
    kubearmor-dev-next: Get:197 http://archive.ubuntu.com/ubuntu impish/main amd64 libsmbios-c2 amd64 2.4.3-1build1 [75.2 kB]
    kubearmor-dev-next: Get:198 http://archive.ubuntu.com/ubuntu impish/main amd64 libudisks2-0 amd64 2.9.4-1 [167 kB]
    kubearmor-dev-next: Get:199 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-headers-5.13.0-20 all 5.13.0-20.20 [12.1 MB]
    kubearmor-dev-next: Get:200 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-headers-5.13.0-20-generic amd64 5.13.0-20.20 [2520 kB]
    kubearmor-dev-next: Get:201 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-modules-5.13.0-20-generic amd64 5.13.0-20.20 [20.1 MB]
    kubearmor-dev-next: Get:202 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-image-5.13.0-20-generic amd64 5.13.0-20.20 [10.1 MB]
    kubearmor-dev-next: Get:203 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-virtual amd64 5.13.0.20.31 [1672 B]
    kubearmor-dev-next: Get:204 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-image-virtual amd64 5.13.0.20.31 [2344 B]
    kubearmor-dev-next: Get:205 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-headers-virtual amd64 5.13.0.20.31 [1632 B]
    kubearmor-dev-next: Get:206 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-headers-generic amd64 5.13.0.20.31 [2268 B]
    kubearmor-dev-next: Get:207 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-debian all 0.1.39ubuntu1 [71.9 kB]
    kubearmor-dev-next: Get:208 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-distutils all 3.9.7-1 [144 kB]
    kubearmor-dev-next: Get:209 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-lib2to3 all 3.9.7-1 [77.9 kB]
    kubearmor-dev-next: Get:210 http://archive.ubuntu.com/ubuntu impish/main amd64 squashfs-tools amd64 1:4.4-2ubuntu2 [124 kB]
    kubearmor-dev-next: Get:211 http://archive.ubuntu.com/ubuntu impish/main amd64 snapd amd64 2.53+21.10ubuntu1 [22.1 MB]
    kubearmor-dev-next: Get:212 http://archive.ubuntu.com/ubuntu impish/main amd64 tmux amd64 3.1c-1build1 [351 kB]
    kubearmor-dev-next: Get:213 http://archive.ubuntu.com/ubuntu impish/main amd64 xfsprogs amd64 5.10.0-4ubuntu2 [860 kB]
    kubearmor-dev-next: Get:214 http://archive.ubuntu.com/ubuntu impish/main amd64 ubuntu-server amd64 1.472 [2786 B]
    kubearmor-dev-next: Get:215 http://archive.ubuntu.com/ubuntu impish/main amd64 udisks2 amd64 2.9.4-1 [285 kB]
    kubearmor-dev-next: Get:216 http://archive.ubuntu.com/ubuntu impish/main amd64 cloud-init all 21.3-1-g6803368d-0ubuntu3 [462 kB]
    kubearmor-dev-next: Get:217 http://archive.ubuntu.com/ubuntu impish/main amd64 libgusb2 amd64 0.3.5-1build1 [24.7 kB]
    kubearmor-dev-next: Get:218 http://archive.ubuntu.com/ubuntu impish/main amd64 zerofree amd64 1.1.1-1build2 [8752 B]
    kubearmor-dev-next: dpkg-preconfigure: unable to re-open stdin: No such file or directory
    kubearmor-dev-next: Fetched 138 MB in 1min 45s (1308 kB/s)
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../motd-news-config_11.1ubuntu5_all.deb ...
    kubearmor-dev-next: Unpacking motd-news-config (11.1ubuntu5) over (11.1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../btrfs-progs_5.10.1-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking btrfs-progs (5.10.1-2build1) over (5.10.1-2) ...
    kubearmor-dev-next: Preparing to unpack .../gcc-11-base_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking gcc-11-base:amd64 (11.2.0-7ubuntu2) over (11.2.0-3ubuntu1) ...
    kubearmor-dev-next: Setting up gcc-11-base:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libgcc-s1_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libgcc-s1:amd64 (11.2.0-7ubuntu2) over (11.2.0-3ubuntu1) ...
    kubearmor-dev-next: Setting up libgcc-s1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libstdc++6_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libstdc++6:amd64 (11.2.0-7ubuntu2) over (11.2.0-3ubuntu1) ...
    kubearmor-dev-next: Setting up libstdc++6:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libcom-err2_1.46.3-1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libcom-err2:amd64 (1.46.3-1ubuntu3) over (1.46.2-1ubuntu2) ...
    kubearmor-dev-next: Setting up libcom-err2:amd64 (1.46.3-1ubuntu3) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../logsave_1.46.3-1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking logsave (1.46.3-1ubuntu3) over (1.46.2-1ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../libext2fs2_1.46.3-1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libext2fs2:amd64 (1.46.3-1ubuntu3) over (1.46.2-1ubuntu2) ...
    kubearmor-dev-next: Setting up libext2fs2:amd64 (1.46.3-1ubuntu3) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../e2fsprogs_1.46.3-1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking e2fsprogs (1.46.3-1ubuntu3) over (1.46.2-1ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../libc6_2.34-0ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libc6:amd64 (2.34-0ubuntu3) over (2.34-0ubuntu2) ...
    kubearmor-dev-next: Setting up libc6:amd64 (2.34-0ubuntu3) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../base-files_11.1ubuntu5_amd64.deb ...
    kubearmor-dev-next: Unpacking base-files (11.1ubuntu5) over (11.1ubuntu3) ...
    kubearmor-dev-next: Setting up base-files (11.1ubuntu5) ...
    kubearmor-dev-next: Installing new version of config file /etc/issue ...
    kubearmor-dev-next: Installing new version of config file /etc/issue.net ...
    kubearmor-dev-next: Installing new version of config file /etc/lsb-release ...
    kubearmor-dev-next: motd-news.service is a disabled or a static unit not running, not starting it.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../bash_5.1-3ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking bash (5.1-3ubuntu2) over (5.1-3ubuntu1) ...
    kubearmor-dev-next: Setting up bash (5.1-3ubuntu2) ...
    kubearmor-dev-next: update-alternatives: using /usr/share/man/man7/bash-builtins.7.gz to provide /usr/share/man/man7/builtins.7.gz (builtins.7.gz) in auto mode
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../dash_0.5.11+git20210120+802ebd4-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking dash (0.5.11+git20210120+802ebd4-1build1) over (0.5.11+git20210120+802ebd4-1) ...
    kubearmor-dev-next: Setting up dash (0.5.11+git20210120+802ebd4-1build1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../grep_3.7-0ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking grep (3.7-0ubuntu1) over (3.6-1) ...
    kubearmor-dev-next: Setting up grep (3.7-0ubuntu1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../hostname_3.23ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking hostname (3.23ubuntu1) over (3.23) ...
    kubearmor-dev-next: Setting up hostname (3.23ubuntu1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../init-system-helpers_1.60build1_all.deb ...
    kubearmor-dev-next: Unpacking init-system-helpers (1.60build1) over (1.60) ...
    kubearmor-dev-next: Setting up init-system-helpers (1.60build1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libc-bin_2.34-0ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libc-bin (2.34-0ubuntu3) over (2.34-0ubuntu2) ...
    kubearmor-dev-next: Setting up libc-bin (2.34-0ubuntu3) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libgcrypt20_1.8.7-5ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libgcrypt20:amd64 (1.8.7-5ubuntu2) over (1.8.7-5ubuntu1) ...
    kubearmor-dev-next: Setting up libgcrypt20:amd64 (1.8.7-5ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libnss-systemd_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking libnss-systemd:amd64 (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../libsystemd0_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking libsystemd0:amd64 (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Setting up libsystemd0:amd64 (248.3-1ubuntu8) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62122 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../0-systemd-timesyncd_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking systemd-timesyncd (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../1-systemd-sysv_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking systemd-sysv (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../2-libpam-systemd_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking libpam-systemd:amd64 (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../3-systemd_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking systemd (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../4-udev_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking udev (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../5-libudev1_248.3-1ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking libudev1:amd64 (248.3-1ubuntu8) over (248.3-1ubuntu3) ...
    kubearmor-dev-next: Setting up libudev1:amd64 (248.3-1ubuntu8) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libacl1_2.2.53-10ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libacl1:amd64 (2.2.53-10ubuntu2) over (2.2.53-10ubuntu1) ...
    kubearmor-dev-next: Setting up libacl1:amd64 (2.2.53-10ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libselinux1_3.1-3build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libselinux1:amd64 (3.1-3build2) over (3.1-3build1) ...
    kubearmor-dev-next: Setting up libselinux1:amd64 (3.1-3build2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libpam0g_1.3.1-5ubuntu11_amd64.deb ...
    kubearmor-dev-next: Unpacking libpam0g:amd64 (1.3.1-5ubuntu11) over (1.3.1-5ubuntu8) ...
    kubearmor-dev-next: Setting up libpam0g:amd64 (1.3.1-5ubuntu11) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libpam-modules-bin_1.3.1-5ubuntu11_amd64.deb ...
    kubearmor-dev-next: Unpacking libpam-modules-bin (1.3.1-5ubuntu11) over (1.3.1-5ubuntu8) ...
    kubearmor-dev-next: Setting up libpam-modules-bin (1.3.1-5ubuntu11) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libpam-modules_1.3.1-5ubuntu11_amd64.deb ...
    kubearmor-dev-next: Unpacking libpam-modules:amd64 (1.3.1-5ubuntu11) over (1.3.1-5ubuntu8) ...
    kubearmor-dev-next: Setting up libpam-modules:amd64 (1.3.1-5ubuntu11) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libpam-runtime_1.3.1-5ubuntu11_all.deb ...
    kubearmor-dev-next: Unpacking libpam-runtime (1.3.1-5ubuntu11) over (1.3.1-5ubuntu8) ...
    kubearmor-dev-next: Setting up libpam-runtime (1.3.1-5ubuntu11) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../dbus_1.12.20-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking dbus (1.12.20-2ubuntu2) over (1.12.20-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../libdbus-1-3_1.12.20-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libdbus-1-3:amd64 (1.12.20-2ubuntu2) over (1.12.20-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../libexpat1_2.4.1-2_amd64.deb ...
    kubearmor-dev-next: Unpacking libexpat1:amd64 (2.4.1-2) over (2.3.0-1) ...
    kubearmor-dev-next: Preparing to unpack .../libdevmapper1.02.1_2%3a1.02.175-2.1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libdevmapper1.02.1:amd64 (2:1.02.175-2.1ubuntu3) over (2:1.02.175-2.1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../libssl1.1_1.1.1l-1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libssl1.1:amd64 (1.1.1l-1ubuntu1) over (1.1.1k-1ubuntu1) ...
    kubearmor-dev-next: Setting up libssl1.1:amd64 (1.1.1l-1ubuntu1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libcryptsetup12_2%3a2.3.6-0ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libcryptsetup12:amd64 (2:2.3.6-0ubuntu1) over (2:2.3.4-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../libxxhash0_0.8.0-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libxxhash0:amd64 (0.8.0-2build1) over (0.8.0-2) ...
    kubearmor-dev-next: Setting up libxxhash0:amd64 (0.8.0-2build1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libapt-pkg6.0_2.3.9_amd64.deb ...
    kubearmor-dev-next: Unpacking libapt-pkg6.0:amd64 (2.3.9) over (2.3.7) ...
    kubearmor-dev-next: Setting up libapt-pkg6.0:amd64 (2.3.9) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../archives/apt_2.3.9_amd64.deb ...
    kubearmor-dev-next: Unpacking apt (2.3.9) over (2.3.7) ...
    kubearmor-dev-next: Setting up apt (2.3.9) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../00-apt-utils_2.3.9_amd64.deb ...
    kubearmor-dev-next: Unpacking apt-utils (2.3.9) over (2.3.7) ...
    kubearmor-dev-next: Preparing to unpack .../01-libglib2.0-bin_2.68.4-1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libglib2.0-bin (2.68.4-1ubuntu1) over (2.68.3-1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../02-libglib2.0-0_2.68.4-1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libglib2.0-0:amd64 (2.68.4-1ubuntu1) over (2.68.3-1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../03-libgirepository-1.0-1_1.68.0-1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libgirepository-1.0-1:amd64 (1.68.0-1build2) over (1.68.0-1) ...
    kubearmor-dev-next: Preparing to unpack .../04-python3-gi_3.40.1-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-gi (3.40.1-1build1) over (3.40.1-1) ...
    kubearmor-dev-next: Preparing to unpack .../05-python3-cffi-backend_1.14.6-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-cffi-backend:amd64 (1.14.6-1build1) over (1.14.6-1) ...
    kubearmor-dev-next: Preparing to unpack .../06-python3.9_3.9.7-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3.9 (3.9.7-2build1) over (3.9.7-1) ...
    kubearmor-dev-next: Preparing to unpack .../07-python3.9-minimal_3.9.7-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3.9-minimal (3.9.7-2build1) over (3.9.7-1) ...
    kubearmor-dev-next: Preparing to unpack .../08-libpython3.9-minimal_3.9.7-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpython3.9-minimal:amd64 (3.9.7-2build1) over (3.9.7-1) ...
    kubearmor-dev-next: Preparing to unpack .../09-libpython3.9_3.9.7-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpython3.9:amd64 (3.9.7-2build1) over (3.9.7-1) ...
    kubearmor-dev-next: Preparing to unpack .../10-libpython3.9-stdlib_3.9.7-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpython3.9-stdlib:amd64 (3.9.7-2build1) over (3.9.7-1) ...
    kubearmor-dev-next: dpkg: libffi8ubuntu1:amd64: dependency problems, but removing anyway as you requested:
    kubearmor-dev-next:  libp11-kit0:amd64 depends on libffi8ubuntu1 (>= 3.4~20200819).
    kubearmor-dev-next: 
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Removing libffi8ubuntu1:amd64 (3.4~20200819gead65ca871-0ubuntu5) ...
    kubearmor-dev-next: Selecting previously unselected package libffi8:amd64.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62118 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libffi8_3.4.2-1ubuntu5_amd64.deb ...
    kubearmor-dev-next: Unpacking libffi8:amd64 (3.4.2-1ubuntu5) ...
    kubearmor-dev-next: Setting up libffi8:amd64 (3.4.2-1ubuntu5) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libp11-kit0_0.23.22-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libp11-kit0:amd64 (0.23.22-1build1) over (0.23.22-1) ...
    kubearmor-dev-next: Setting up libp11-kit0:amd64 (0.23.22-1build1) ...
    kubearmor-dev-next: Setting up libdevmapper1.02.1:amd64 (2:1.02.175-2.1ubuntu3) ...
    kubearmor-dev-next: Setting up libcryptsetup12:amd64 (2:2.3.6-0ubuntu1) ...
    kubearmor-dev-next: Setting up systemd-timesyncd (248.3-1ubuntu8) ...
    kubearmor-dev-next: Setting up systemd (248.3-1ubuntu8) ...
    kubearmor-dev-next: Setting up systemd-sysv (248.3-1ubuntu8) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../init_1.60build1_amd64.deb ...
    kubearmor-dev-next: Unpacking init (1.60build1) over (1.60) ...
    kubearmor-dev-next: Setting up libpython3.9-minimal:amd64 (3.9.7-2build1) ...
    kubearmor-dev-next: Setting up libexpat1:amd64 (2.4.1-2) ...
    kubearmor-dev-next: Setting up python3.9-minimal (3.9.7-2build1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../python3-minimal_3.9.4-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-minimal (3.9.4-1build1) over (3.9.4-1) ...
    kubearmor-dev-next: Setting up python3-minimal (3.9.4-1build1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62123 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../python3_3.9.4-1build1_amd64.deb ...
    kubearmor-dev-next: running python pre-rtupdate hooks for python3.9...
    kubearmor-dev-next: Unpacking python3 (3.9.4-1build1) over (3.9.4-1) ...
    kubearmor-dev-next: Preparing to unpack .../tzdata_2021a-2ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking tzdata (2021a-2ubuntu1) over (2021a-1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../libmpdec3_2.5.1-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libmpdec3:amd64 (2.5.1-2build1) over (2.5.1-2) ...
    kubearmor-dev-next: Preparing to unpack .../libtirpc-common_1.3.2-2_all.deb ...
    kubearmor-dev-next: Unpacking libtirpc-common (1.3.2-2) over (1.3.1-1build1) ...
    kubearmor-dev-next: Setting up libtirpc-common (1.3.2-2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62124 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libtirpc3_1.3.2-2_amd64.deb ...
    kubearmor-dev-next: Unpacking libtirpc3:amd64 (1.3.2-2) over (1.3.1-1build1) ...
    kubearmor-dev-next: Setting up libtirpc3:amd64 (1.3.2-2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62125 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libnsl2_1.3.0-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libnsl2:amd64 (1.3.0-2build1) over (1.3.0-2) ...
    kubearmor-dev-next: Setting up libnsl2:amd64 (1.3.0-2build1) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62125 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../00-libpython3-stdlib_3.9.4-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpython3-stdlib:amd64 (3.9.4-1build1) over (3.9.4-1) ...
    kubearmor-dev-next: Preparing to unpack .../01-libestr0_0.1.10-2.1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libestr0:amd64 (0.1.10-2.1build2) over (0.1.10-2.1build1) ...
    kubearmor-dev-next: Preparing to unpack .../02-libfastjson4_0.99.9-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libfastjson4:amd64 (0.99.9-1build1) over (0.99.9-1) ...
    kubearmor-dev-next: Preparing to unpack .../03-rsyslog_8.2102.0-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking rsyslog (8.2102.0-2ubuntu2) over (8.2102.0-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../04-libglib2.0-data_2.68.4-1ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking libglib2.0-data (2.68.4-1ubuntu1) over (2.68.3-1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../05-libdw1_0.185-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libdw1:amd64 (0.185-1build1) over (0.185-1) ...
    kubearmor-dev-next: Preparing to unpack .../06-libelf1_0.185-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libelf1:amd64 (0.185-1build1) over (0.185-1) ...
    kubearmor-dev-next: Preparing to unpack .../07-irqbalance_1.7.0-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking irqbalance (1.7.0-1build1) over (1.7.0-1) ...
    kubearmor-dev-next: Preparing to unpack .../08-ntfs-3g_1%3a2017.3.23AR.3-3ubuntu5_amd64.deb ...
    kubearmor-dev-next: Unpacking ntfs-3g (1:2017.3.23AR.3-3ubuntu5) over (1:2017.3.23AR.3-3ubuntu4) ...
    kubearmor-dev-next: Preparing to unpack .../09-libntfs-3g883_1%3a2017.3.23AR.3-3ubuntu5_amd64.deb ...
    kubearmor-dev-next: Unpacking libntfs-3g883 (1:2017.3.23AR.3-3ubuntu5) over (1:2017.3.23AR.3-3ubuntu4) ...
    kubearmor-dev-next: Preparing to unpack .../10-accountsservice_0.6.55-0ubuntu14_amd64.deb ...
    kubearmor-dev-next: Unpacking accountsservice (0.6.55-0ubuntu14) over (0.6.55-0ubuntu13.2) ...
    kubearmor-dev-next: Preparing to unpack .../11-libaccountsservice0_0.6.55-0ubuntu14_amd64.deb ...
    kubearmor-dev-next: Unpacking libaccountsservice0:amd64 (0.6.55-0ubuntu14) over (0.6.55-0ubuntu13.2) ...
    kubearmor-dev-next: Preparing to unpack .../12-language-selector-common_0.216_all.deb ...
    kubearmor-dev-next: Unpacking language-selector-common (0.216) over (0.214) ...
    kubearmor-dev-next: Preparing to unpack .../13-libdevmapper-event1.02.1_2%3a1.02.175-2.1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libdevmapper-event1.02.1:amd64 (2:1.02.175-2.1ubuntu3) over (2:1.02.175-2.1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../14-libedit2_3.1-20191231-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libedit2:amd64 (3.1-20191231-2build1) over (3.1-20191231-2) ...
    kubearmor-dev-next: Preparing to unpack .../15-lsb-base_11.1.0ubuntu3_all.deb ...
    kubearmor-dev-next: Unpacking lsb-base (11.1.0ubuntu3) over (11.1.0ubuntu2) ...
    kubearmor-dev-next: Setting up lsb-base (11.1.0ubuntu3) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62125 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../00-dmsetup_2%3a1.02.175-2.1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking dmsetup (2:1.02.175-2.1ubuntu3) over (2:1.02.175-2.1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../01-liblvm2cmd2.03_2.03.11-2.1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking liblvm2cmd2.03:amd64 (2.03.11-2.1ubuntu3) over (2.03.11-2.1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../02-dmeventd_2%3a1.02.175-2.1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking dmeventd (2:1.02.175-2.1ubuntu3) over (2:1.02.175-2.1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../03-lvm2_2.03.11-2.1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking lvm2 (2.03.11-2.1ubuntu3) over (2.03.11-2.1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../04-libdrm-common_2.4.107-8ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking libdrm-common (2.4.107-8ubuntu1) over (2.4.107-1) ...
    kubearmor-dev-next: Preparing to unpack .../05-libdrm2_2.4.107-8ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libdrm2:amd64 (2.4.107-8ubuntu1) over (2.4.107-1) ...
    kubearmor-dev-next: Preparing to unpack .../06-libmspack0_0.10.1-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libmspack0:amd64 (0.10.1-2build1) over (0.10.1-2) ...
    kubearmor-dev-next: Preparing to unpack .../07-libxml2_2.9.12+dfsg-4_amd64.deb ...
    kubearmor-dev-next: Unpacking libxml2:amd64 (2.9.12+dfsg-4) over (2.9.12+dfsg-3) ...
    kubearmor-dev-next: Preparing to unpack .../08-libxmlsec1_1.2.32-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libxmlsec1:amd64 (1.2.32-1build1) over (1.2.32-1) ...
    kubearmor-dev-next: Preparing to unpack .../09-libxmlsec1-openssl_1.2.32-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libxmlsec1-openssl:amd64 (1.2.32-1build1) over (1.2.32-1) ...
    kubearmor-dev-next: Preparing to unpack .../10-distro-info-data_0.51ubuntu1.1_all.deb ...
    kubearmor-dev-next: Unpacking distro-info-data (0.51ubuntu1.1) over (0.51) ...
    kubearmor-dev-next: Preparing to unpack .../11-lsb-release_11.1.0ubuntu3_all.deb ...
    kubearmor-dev-next: Unpacking lsb-release (11.1.0ubuntu3) over (11.1.0ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../12-open-vm-tools_2%3a11.3.0-2ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking open-vm-tools (2:11.3.0-2ubuntu1) over (2:11.3.0-2) ...
    kubearmor-dev-next: Preparing to unpack .../13-libattr1_1%3a2.4.48-6build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libattr1:amd64 (1:2.4.48-6build2) over (1:2.4.48-6build1) ...
    kubearmor-dev-next: Setting up libattr1:amd64 (1:2.4.48-6build2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62126 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libsepol1_3.1-1ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libsepol1:amd64 (3.1-1ubuntu2) over (3.1-1ubuntu1) ...
    kubearmor-dev-next: Setting up libsepol1:amd64 (3.1-1ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62126 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libsemanage-common_3.1-1ubuntu2_all.deb ...
    kubearmor-dev-next: Unpacking libsemanage-common (3.1-1ubuntu2) over (3.1-1ubuntu1) ...
    kubearmor-dev-next: Setting up libsemanage-common (3.1-1ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62126 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libsemanage1_3.1-1ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libsemanage1:amd64 (3.1-1ubuntu2) over (3.1-1ubuntu1) ...
    kubearmor-dev-next: Setting up libsemanage1:amd64 (3.1-1ubuntu2) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62126 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libunistring2_0.9.10-6_amd64.deb ...
    kubearmor-dev-next: Unpacking libunistring2:amd64 (0.9.10-6) over (0.9.10-4) ...
    kubearmor-dev-next: Setting up libunistring2:amd64 (0.9.10-6) ...
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 62126 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../000-libss2_1.46.3-1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libss2:amd64 (1.46.3-1ubuntu3) over (1.46.2-1ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../001-openssl_1.1.1l-1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking openssl (1.1.1l-1ubuntu1) over (1.1.1k-1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../002-ca-certificates_20210119ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking ca-certificates (20210119ubuntu1) over (20210119build1) ...
    kubearmor-dev-next: Preparing to unpack .../003-gir1.2-glib-2.0_1.68.0-1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking gir1.2-glib-2.0:amd64 (1.68.0-1build2) over (1.68.0-1) ...
    kubearmor-dev-next: Preparing to unpack .../004-kbd_2.3.0-3ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking kbd (2.3.0-3ubuntu3) over (2.3.0-3ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../005-libatm1_1%3a2.5.1-4build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libatm1:amd64 (1:2.5.1-4build1) over (1:2.5.1-4) ...
    kubearmor-dev-next: Preparing to unpack .../006-libfribidi0_1.0.8-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libfribidi0:amd64 (1.0.8-2ubuntu2) over (1.0.8-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../007-libnetplan0_0.103-0ubuntu7_amd64.deb ...
    kubearmor-dev-next: Unpacking libnetplan0:amd64 (0.103-0ubuntu7) over (0.103-0ubuntu5) ...
    kubearmor-dev-next: Preparing to unpack .../008-python3-newt_0.52.21-4ubuntu7_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-newt:amd64 (0.52.21-4ubuntu7) over (0.52.21-4ubuntu6) ...
    kubearmor-dev-next: Preparing to unpack .../009-libnewt0.52_0.52.21-4ubuntu7_amd64.deb ...
    kubearmor-dev-next: Unpacking libnewt0.52:amd64 (0.52.21-4ubuntu7) over (0.52.21-4ubuntu6) ...
    kubearmor-dev-next: Preparing to unpack .../010-locales_2.34-0ubuntu3_all.deb ...
    kubearmor-dev-next: Unpacking locales (2.34-0ubuntu3) over (2.34-0ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../011-netplan.io_0.103-0ubuntu7_amd64.deb ...
    kubearmor-dev-next: Unpacking netplan.io (0.103-0ubuntu7) over (0.103-0ubuntu5) ...
    kubearmor-dev-next: Preparing to unpack .../012-xxd_2%3a8.2.2434-3ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking xxd (2:8.2.2434-3ubuntu3) over (2:8.2.2434-3ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../013-vim_2%3a8.2.2434-3ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking vim (2:8.2.2434-3ubuntu3) over (2:8.2.2434-3ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../014-vim-tiny_2%3a8.2.2434-3ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking vim-tiny (2:8.2.2434-3ubuntu3) over (2:8.2.2434-3ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../015-vim-runtime_2%3a8.2.2434-3ubuntu3_all.deb ...
    kubearmor-dev-next: Unpacking vim-runtime (2:8.2.2434-3ubuntu3) over (2:8.2.2434-3ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../016-vim-common_2%3a8.2.2434-3ubuntu3_all.deb ...
    kubearmor-dev-next: Unpacking vim-common (2:8.2.2434-3ubuntu3) over (2:8.2.2434-3ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../017-libgpm2_1.20.7-8build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libgpm2:amd64 (1.20.7-8build1) over (1.20.7-8) ...
    kubearmor-dev-next: Preparing to unpack .../018-whiptail_0.52.21-4ubuntu7_amd64.deb ...
    kubearmor-dev-next: Unpacking whiptail (0.52.21-4ubuntu7) over (0.52.21-4ubuntu6) ...
    kubearmor-dev-next: Preparing to unpack .../019-ubuntu-minimal_1.472_amd64.deb ...
    kubearmor-dev-next: Unpacking ubuntu-minimal (1.472) over (1.471) ...
    kubearmor-dev-next: Preparing to unpack .../020-xdg-user-dirs_0.17-2ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking xdg-user-dirs (0.17-2ubuntu3) over (0.17-2ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../021-busybox-static_1%3a1.30.1-6ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking busybox-static (1:1.30.1-6ubuntu3) over (1:1.30.1-6ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../022-python3-gdbm_3.9.7-1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-gdbm:amd64 (3.9.7-1) over (3.9.5-0ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../023-command-not-found_21.10.0_all.deb ...
    kubearmor-dev-next: Unpacking command-not-found (21.10.0) over (20.10.1) ...
    kubearmor-dev-next: Preparing to unpack .../024-python3-commandnotfound_21.10.0_all.deb ...
    kubearmor-dev-next: Unpacking python3-commandnotfound (21.10.0) over (20.10.1) ...
    kubearmor-dev-next: Preparing to unpack .../025-dosfstools_4.2-1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking dosfstools (4.2-1build2) over (4.2-1build1) ...
    kubearmor-dev-next: Preparing to unpack .../026-libuchardet0_0.0.7-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libuchardet0:amd64 (0.0.7-1build1) over (0.0.7-1) ...
    kubearmor-dev-next: Preparing to unpack .../027-groff-base_1.22.4-7_amd64.deb ...
    kubearmor-dev-next: Unpacking groff-base (1.22.4-7) over (1.22.4-6) ...
    kubearmor-dev-next: Preparing to unpack .../028-hdparm_9.60+ds-1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking hdparm (9.60+ds-1build2) over (9.60+ds-1build1) ...
    kubearmor-dev-next: Preparing to unpack .../029-libfido2-1_1.6.0-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libfido2-1:amd64 (1.6.0-2build1) over (1.6.0-2) ...
    kubearmor-dev-next: Preparing to unpack .../030-libpcap0.8_1.10.0-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpcap0.8:amd64 (1.10.0-2build1) over (1.10.0-2) ...
    kubearmor-dev-next: Preparing to unpack .../031-libpipeline1_1.5.3-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpipeline1:amd64 (1.5.3-1build1) over (1.5.3-1) ...
    kubearmor-dev-next: Preparing to unpack .../032-libpng16-16_1.6.37-3build4_amd64.deb ...
    kubearmor-dev-next: Unpacking libpng16-16:amd64 (1.6.37-3build4) over (1.6.37-3build3) ...
    kubearmor-dev-next: Preparing to unpack .../033-libplymouth5_0.9.5git20210406-0ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libplymouth5:amd64 (0.9.5git20210406-0ubuntu2) over (0.9.5git20210323-0ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../034-libuv1_1.40.0-2ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libuv1:amd64 (1.40.0-2ubuntu1) over (1.40.0-2) ...
    kubearmor-dev-next: Preparing to unpack .../035-libxdmcp6_1%3a1.1.3-0ubuntu4_amd64.deb ...
    kubearmor-dev-next: Unpacking libxdmcp6:amd64 (1:1.1.3-0ubuntu4) over (1:1.1.3-0ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../036-ltrace_0.7.3-6.1ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking ltrace (0.7.3-6.1ubuntu3) over (0.7.3-6.1ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../037-mtr-tiny_0.94-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking mtr-tiny (0.94-1build1) over (0.94-1) ...
    kubearmor-dev-next: Preparing to unpack .../038-openssh-sftp-server_1%3a8.4p1-6ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking openssh-sftp-server (1:8.4p1-6ubuntu2) over (1:8.4p1-5ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../039-openssh-server_1%3a8.4p1-6ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking openssh-server (1:8.4p1-6ubuntu2) over (1:8.4p1-5ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../040-openssh-client_1%3a8.4p1-6ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking openssh-client (1:8.4p1-6ubuntu2) over (1:8.4p1-5ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../041-plymouth-theme-ubuntu-text_0.9.5git20210406-0ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking plymouth-theme-ubuntu-text (0.9.5git20210406-0ubuntu2) over (0.9.5git20210323-0ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../042-libpackagekit-glib2-18_1.2.2-2ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libpackagekit-glib2-18:amd64 (1.2.2-2ubuntu3) over (1.2.2-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../043-packagekit-tools_1.2.2-2ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking packagekit-tools (1.2.2-2ubuntu3) over (1.2.2-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../044-libbrotli1_1.0.9-2build3_amd64.deb ...
    kubearmor-dev-next: Unpacking libbrotli1:amd64 (1.0.9-2build3) over (1.0.9-2build2) ...
    kubearmor-dev-next: Preparing to unpack .../045-librtmp1_2.4+20151223.gitfa8646d.1-2build3_amd64.deb ...
    kubearmor-dev-next: Unpacking librtmp1:amd64 (2.4+20151223.gitfa8646d.1-2build3) over (2.4+20151223.gitfa8646d.1-2build2) ...
    kubearmor-dev-next: Preparing to unpack .../046-libcurl3-gnutls_7.74.0-1.3ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libcurl3-gnutls:amd64 (7.74.0-1.3ubuntu2) over (7.74.0-1.2ubuntu4) ...
    kubearmor-dev-next: Preparing to unpack .../047-libappstream4_0.14.5-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libappstream4:amd64 (0.14.5-1) over (0.14.4-1) ...
    kubearmor-dev-next: Preparing to unpack .../048-libgstreamer1.0-0_1.18.5-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libgstreamer1.0-0:amd64 (1.18.5-1) over (1.18.4-2.1) ...
    kubearmor-dev-next: Preparing to unpack .../049-packagekit_1.2.2-2ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking packagekit (1.2.2-2ubuntu3) over (1.2.2-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../050-plymouth_0.9.5git20210406-0ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking plymouth (0.9.5git20210406-0ubuntu2) over (0.9.5git20210323-0ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../051-ubuntu-release-upgrader-core_1%3a21.10.8_all.deb ...
    kubearmor-dev-next: Unpacking ubuntu-release-upgrader-core (1:21.10.8) over (1:21.10.7) ...
    kubearmor-dev-next: Preparing to unpack .../052-python3-distupgrade_1%3a21.10.8_all.deb ...
    kubearmor-dev-next: Unpacking python3-distupgrade (1:21.10.8) over (1:21.10.7) ...
    kubearmor-dev-next: Preparing to unpack .../053-usbutils_1%3a013-3build1_amd64.deb ...
    kubearmor-dev-next: Unpacking usbutils (1:013-3build1) over (1:013-3) ...
    kubearmor-dev-next: Preparing to unpack .../054-ubuntu-standard_1.472_amd64.deb ...
    kubearmor-dev-next: Unpacking ubuntu-standard (1.472) over (1.471) ...
    kubearmor-dev-next: Preparing to unpack .../055-ufw_0.36.1-1_all.deb ...
    kubearmor-dev-next: Unpacking ufw (0.36.1-1) over (0.36-7.1) ...
    kubearmor-dev-next: Preparing to unpack .../056-libefivar1_37-6ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libefivar1:amd64 (37-6ubuntu2) over (37-6ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../057-libefiboot1_37-6ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libefiboot1:amd64 (37-6ubuntu2) over (37-6ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../058-grub-pc_2.04-1ubuntu47_amd64.deb ...
    kubearmor-dev-next: Unpacking grub-pc (2.04-1ubuntu47) over (2.04-1ubuntu46) ...
    kubearmor-dev-next: Preparing to unpack .../059-grub2-common_2.04-1ubuntu47_amd64.deb ...
    kubearmor-dev-next: Unpacking grub2-common (2.04-1ubuntu47) over (2.04-1ubuntu46) ...
    kubearmor-dev-next: Preparing to unpack .../060-grub-pc-bin_2.04-1ubuntu47_amd64.deb ...
    kubearmor-dev-next: Unpacking grub-pc-bin (2.04-1ubuntu47) over (2.04-1ubuntu46) ...
    kubearmor-dev-next: Preparing to unpack .../061-grub-common_2.04-1ubuntu47_amd64.deb ...
    kubearmor-dev-next: Unpacking grub-common (2.04-1ubuntu47) over (2.04-1ubuntu46) ...
    kubearmor-dev-next: Preparing to unpack .../062-python3-problem-report_2.20.11-0ubuntu70_all.deb ...
    kubearmor-dev-next: Unpacking python3-problem-report (2.20.11-0ubuntu70) over (2.20.11-0ubuntu68) ...
    kubearmor-dev-next: Preparing to unpack .../063-python3-apport_2.20.11-0ubuntu70_all.deb ...
    kubearmor-dev-next: Unpacking python3-apport (2.20.11-0ubuntu70) over (2.20.11-0ubuntu68) ...
    kubearmor-dev-next: Preparing to unpack .../064-apport_2.20.11-0ubuntu70_all.deb ...
    kubearmor-dev-next: Unpacking apport (2.20.11-0ubuntu70) over (2.20.11-0ubuntu68) ...
    kubearmor-dev-next: Preparing to unpack .../065-bc_1.07.1-2build3_amd64.deb ...
    kubearmor-dev-next: Unpacking bc (1.07.1-2build3) over (1.07.1-2build2) ...
    kubearmor-dev-next: Preparing to unpack .../066-bcache-tools_1.0.8-4ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking bcache-tools (1.0.8-4ubuntu2) over (1.0.8-4ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../067-libctf0_2.37-7ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libctf0:amd64 (2.37-7ubuntu1) over (2.37-5ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../068-libctf-nobfd0_2.37-7ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libctf-nobfd0:amd64 (2.37-7ubuntu1) over (2.37-5ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../069-binutils-x86-64-linux-gnu_2.37-7ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking binutils-x86-64-linux-gnu (2.37-7ubuntu1) over (2.37-5ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../070-libbinutils_2.37-7ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libbinutils:amd64 (2.37-7ubuntu1) over (2.37-5ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../071-binutils_2.37-7ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking binutils (2.37-7ubuntu1) over (2.37-5ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../072-binutils-common_2.37-7ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking binutils-common:amd64 (2.37-7ubuntu1) over (2.37-5ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../073-bolt_0.9.1-2_amd64.deb ...
    kubearmor-dev-next: Unpacking bolt (0.9.1-2) over (0.9.1-1) ...
    kubearmor-dev-next: Preparing to unpack .../074-busybox-initramfs_1%3a1.30.1-6ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking busybox-initramfs (1:1.30.1-6ubuntu3) over (1:1.30.1-6ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../075-cryptsetup-initramfs_2%3a2.3.6-0ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking cryptsetup-initramfs (2:2.3.6-0ubuntu1) over (2:2.3.4-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../076-cryptsetup-bin_2%3a2.3.6-0ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking cryptsetup-bin (2:2.3.6-0ubuntu1) over (2:2.3.4-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../077-cryptsetup_2%3a2.3.6-0ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking cryptsetup (2:2.3.6-0ubuntu1) over (2:2.3.4-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../078-cryptsetup-run_2%3a2.3.6-0ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking cryptsetup-run (2:2.3.6-0ubuntu1) over (2:2.3.4-1ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../079-curl_7.74.0-1.3ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking curl (7.74.0-1.3ubuntu2) over (7.74.0-1.2ubuntu4) ...
    kubearmor-dev-next: Preparing to unpack .../080-libcurl4_7.74.0-1.3ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libcurl4:amd64 (7.74.0-1.3ubuntu2) over (7.74.0-1.2ubuntu4) ...
    kubearmor-dev-next: Preparing to unpack .../081-libeatmydata1_105-9build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libeatmydata1:amd64 (105-9build2) over (105-9build1) ...
    kubearmor-dev-next: Preparing to unpack .../082-eatmydata_105-9build2_all.deb ...
    kubearmor-dev-next: Unpacking eatmydata (105-9build2) over (105-9build1) ...
    kubearmor-dev-next: Preparing to unpack .../083-ethtool_1%3a5.9-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking ethtool (1:5.9-1build1) over (1:5.9-1) ...
    kubearmor-dev-next: Preparing to unpack .../084-gir1.2-packagekitglib-1.0_1.2.2-2ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking gir1.2-packagekitglib-1.0 (1.2.2-2ubuntu3) over (1.2.2-2ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../085-htop_3.0.5-7build1_amd64.deb ...
    kubearmor-dev-next: Unpacking htop (3.0.5-7build1) over (3.0.5-7) ...
    kubearmor-dev-next: Preparing to unpack .../086-landscape-common_19.12-0ubuntu10_amd64.deb ...
    kubearmor-dev-next: Unpacking landscape-common (19.12-0ubuntu10) over (19.12-0ubuntu9.1) ...
    kubearmor-dev-next: Preparing to unpack .../087-libblockdev-utils2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev-utils2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../088-libvolume-key1_0.3.12-3.1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libvolume-key1 (0.3.12-3.1build2) over (0.3.12-3.1build1) ...
    kubearmor-dev-next: Preparing to unpack .../089-libblockdev-crypto2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev-crypto2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../090-libblockdev-part-err2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev-part-err2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../091-libblockdev-fs2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev-fs2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../092-libblockdev-loop2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev-loop2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../093-libblockdev-part2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev-part2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../094-libblockdev-swap2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev-swap2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../095-libblockdev2_2.25-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libblockdev2:amd64 (2.25-2build1) over (2.25-2) ...
    kubearmor-dev-next: Preparing to unpack .../096-libgcab-1.0-0_1.4-3build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libgcab-1.0-0:amd64 (1.4-3build1) over (1.4-3) ...
    kubearmor-dev-next: Preparing to unpack .../097-libjcat1_0.1.3-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libjcat1:amd64 (0.1.3-2build1) over (0.1.3-2) ...
    kubearmor-dev-next: Preparing to unpack .../098-libproc-processtable-perl_0.59-2build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libproc-processtable-perl (0.59-2build2) over (0.59-2build1) ...
    kubearmor-dev-next: Preparing to unpack .../099-libsigsegv2_2.13-1ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libsigsegv2:amd64 (2.13-1ubuntu2) over (2.13-1ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../100-libsmbios-c2_2.4.3-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libsmbios-c2 (2.4.3-1build1) over (2.4.3-1) ...
    kubearmor-dev-next: Preparing to unpack .../101-libudisks2-0_2.9.4-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libudisks2-0:amd64 (2.9.4-1) over (2.9.3-1) ...
    kubearmor-dev-next: Selecting previously unselected package linux-headers-5.13.0-20.
    kubearmor-dev-next: Preparing to unpack .../102-linux-headers-5.13.0-20_5.13.0-20.20_all.deb ...
    kubearmor-dev-next: Unpacking linux-headers-5.13.0-20 (5.13.0-20.20) ...
    kubearmor-dev-next: Selecting previously unselected package linux-headers-5.13.0-20-generic.
    kubearmor-dev-next: Preparing to unpack .../103-linux-headers-5.13.0-20-generic_5.13.0-20.20_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-headers-5.13.0-20-generic (5.13.0-20.20) ...
    kubearmor-dev-next: Selecting previously unselected package linux-modules-5.13.0-20-generic.
    kubearmor-dev-next: Preparing to unpack .../104-linux-modules-5.13.0-20-generic_5.13.0-20.20_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-modules-5.13.0-20-generic (5.13.0-20.20) ...
    kubearmor-dev-next: Selecting previously unselected package linux-image-5.13.0-20-generic.
    kubearmor-dev-next: Preparing to unpack .../105-linux-image-5.13.0-20-generic_5.13.0-20.20_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-image-5.13.0-20-generic (5.13.0-20.20) ...
    kubearmor-dev-next: Preparing to unpack .../106-linux-virtual_5.13.0.20.31_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-virtual (5.13.0.20.31) over (5.13.0.14.25) ...
    kubearmor-dev-next: Preparing to unpack .../107-linux-image-virtual_5.13.0.20.31_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-image-virtual (5.13.0.20.31) over (5.13.0.14.25) ...
    kubearmor-dev-next: Preparing to unpack .../108-linux-headers-virtual_5.13.0.20.31_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-headers-virtual (5.13.0.20.31) over (5.13.0.14.25) ...
    kubearmor-dev-next: Preparing to unpack .../109-linux-headers-generic_5.13.0.20.31_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-headers-generic (5.13.0.20.31) over (5.13.0.14.25) ...
    kubearmor-dev-next: Preparing to unpack .../110-python3-debian_0.1.39ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking python3-debian (0.1.39ubuntu1) over (0.1.39) ...
    kubearmor-dev-next: Preparing to unpack .../111-python3-distutils_3.9.7-1_all.deb ...
    kubearmor-dev-next: Unpacking python3-distutils (3.9.7-1) over (3.9.5-0ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../112-python3-lib2to3_3.9.7-1_all.deb ...
    kubearmor-dev-next: Unpacking python3-lib2to3 (3.9.7-1) over (3.9.5-0ubuntu3) ...
    kubearmor-dev-next: Preparing to unpack .../113-squashfs-tools_1%3a4.4-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking squashfs-tools (1:4.4-2ubuntu2) over (1:4.4-2) ...
    kubearmor-dev-next: Preparing to unpack .../114-snapd_2.53+21.10ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking snapd (2.53+21.10ubuntu1) over (2.51.1+21.10) ...
    kubearmor-dev-next: Preparing to unpack .../115-tmux_3.1c-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking tmux (3.1c-1build1) over (3.1c-1) ...
    kubearmor-dev-next: Preparing to unpack .../116-xfsprogs_5.10.0-4ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking xfsprogs (5.10.0-4ubuntu2) over (5.10.0-4ubuntu1) ...
    kubearmor-dev-next: Preparing to unpack .../117-ubuntu-server_1.472_amd64.deb ...
    kubearmor-dev-next: Unpacking ubuntu-server (1.472) over (1.471) ...
    kubearmor-dev-next: Preparing to unpack .../118-udisks2_2.9.4-1_amd64.deb ...
    kubearmor-dev-next: Unpacking udisks2 (2.9.4-1) over (2.9.3-1) ...
    kubearmor-dev-next: Preparing to unpack .../119-cloud-init_21.3-1-g6803368d-0ubuntu3_all.deb ...
    kubearmor-dev-next: Unpacking cloud-init (21.3-1-g6803368d-0ubuntu3) over (21.3-1-g6803368d-0ubuntu2) ...
    kubearmor-dev-next: Preparing to unpack .../120-libgusb2_0.3.5-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libgusb2:amd64 (0.3.5-1build1) over (0.3.5-1) ...
    kubearmor-dev-next: Preparing to unpack .../121-zerofree_1.1.1-1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking zerofree (1.1.1-1build2) over (1.1.1-1build1) ...
    kubearmor-dev-next: Setting up cryptsetup-bin (2:2.3.6-0ubuntu1) ...
    kubearmor-dev-next: Setting up libpipeline1:amd64 (1.5.3-1build1) ...
    kubearmor-dev-next: Setting up motd-news-config (11.1ubuntu5) ...
    kubearmor-dev-next: Setting up bcache-tools (1.0.8-4ubuntu2) ...
    kubearmor-dev-next: Setting up zerofree (1.1.1-1build2) ...
    kubearmor-dev-next: Setting up libxdmcp6:amd64 (1:1.1.3-0ubuntu4) ...
    kubearmor-dev-next: Setting up libnewt0.52:amd64 (0.52.21-4ubuntu7) ...
    kubearmor-dev-next: Setting up apt-utils (2.3.9) ...
    kubearmor-dev-next: Setting up libgpm2:amd64 (1.20.7-8build1) ...
    kubearmor-dev-next: Setting up libdevmapper-event1.02.1:amd64 (2:1.02.175-2.1ubuntu3) ...
    kubearmor-dev-next: Setting up init (1.60build1) ...
    kubearmor-dev-next: Setting up squashfs-tools (1:4.4-2ubuntu2) ...
    kubearmor-dev-next: Setting up xdg-user-dirs (0.17-2ubuntu3) ...
    kubearmor-dev-next: Setting up libglib2.0-0:amd64 (2.68.4-1ubuntu1) ...
    kubearmor-dev-next: No schema files found: doing nothing.
    kubearmor-dev-next: Setting up distro-info-data (0.51ubuntu1.1) ...
    kubearmor-dev-next: Setting up htop (3.0.5-7build1) ...
    kubearmor-dev-next: Setting up libestr0:amd64 (0.1.10-2.1build2) ...
    kubearmor-dev-next: Setting up libfastjson4:amd64 (0.99.9-1build1) ...
    kubearmor-dev-next: Setting up libgusb2:amd64 (0.3.5-1build1) ...
    kubearmor-dev-next: Setting up btrfs-progs (5.10.1-2build1) ...
    kubearmor-dev-next: Setting up libbrotli1:amd64 (1.0.9-2build3) ...
    kubearmor-dev-next: Setting up libedit2:amd64 (3.1-20191231-2build1) ...
    kubearmor-dev-next: Setting up libmspack0:amd64 (0.10.1-2build1) ...
    kubearmor-dev-next: Setting up dosfstools (4.2-1build2) ...
    kubearmor-dev-next: Setting up rsyslog (8.2102.0-2ubuntu2) ...
    kubearmor-dev-next: The user `syslog' is already a member of `adm'.
    kubearmor-dev-next: Skipping profile in /etc/apparmor.d/disable: usr.sbin.rsyslogd
    kubearmor-dev-next: Setting up binutils-common:amd64 (2.37-7ubuntu1) ...
    kubearmor-dev-next: Setting up bc (1.07.1-2build3) ...
    kubearmor-dev-next: Setting up libctf-nobfd0:amd64 (2.37-7ubuntu1) ...
    kubearmor-dev-next: Setting up libnetplan0:amd64 (0.103-0ubuntu7) ...
    kubearmor-dev-next: Setting up libpackagekit-glib2-18:amd64 (1.2.2-2ubuntu3) ...
    kubearmor-dev-next: Setting up libnss-systemd:amd64 (248.3-1ubuntu8) ...
    kubearmor-dev-next: Setting up libntfs-3g883 (1:2017.3.23AR.3-3ubuntu5) ...
    kubearmor-dev-next: Setting up hdparm (9.60+ds-1build2) ...
    kubearmor-dev-next: Setting up libatm1:amd64 (1:2.5.1-4build1) ...
    kubearmor-dev-next: Setting up locales (2.34-0ubuntu3) ...
    kubearmor-dev-next: Generating locales (this might take a while)...
    kubearmor-dev-next:   en_US.UTF-8... done
    kubearmor-dev-next: Generation complete.
    kubearmor-dev-next: Setting up usbutils (1:013-3build1) ...
    kubearmor-dev-next: Setting up xxd (2:8.2.2434-3ubuntu3) ...
    kubearmor-dev-next: Setting up ntfs-3g (1:2017.3.23AR.3-3ubuntu5) ...
    kubearmor-dev-next: Setting up libjcat1:amd64 (0.1.3-2build1) ...
    kubearmor-dev-next: Setting up tzdata (2021a-2ubuntu1) ...
    kubearmor-dev-next: 
    kubearmor-dev-next: Current default time zone: 'Etc/UTC'
    kubearmor-dev-next: Local time is now:      Wed Oct 20 20:48:15 UTC 2021.
    kubearmor-dev-next: Universal Time is now:  Wed Oct 20 20:48:15 UTC 2021.
    kubearmor-dev-next: Run 'dpkg-reconfigure tzdata' if you wish to change it.
    kubearmor-dev-next: 
    kubearmor-dev-next: Setting up libglib2.0-data (2.68.4-1ubuntu1) ...
    kubearmor-dev-next: Setting up libuv1:amd64 (1.40.0-2ubuntu1) ...
    kubearmor-dev-next: Setting up vim-common (2:8.2.2434-3ubuntu3) ...
    kubearmor-dev-next: Setting up busybox-static (1:1.30.1-6ubuntu3) ...
    kubearmor-dev-next: Setting up libblockdev-utils2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up mtr-tiny (0.94-1build1) ...
    kubearmor-dev-next: Setting up librtmp1:amd64 (2.4+20151223.gitfa8646d.1-2build3) ...
    kubearmor-dev-next: Setting up libsmbios-c2 (2.4.3-1build1) ...
    kubearmor-dev-next: Setting up libdbus-1-3:amd64 (1.12.20-2ubuntu2) ...
    kubearmor-dev-next: Setting up dbus (1.12.20-2ubuntu2) ...
    kubearmor-dev-next: A reboot is required to replace the running dbus-daemon.
    kubearmor-dev-next: Please reboot the system when convenient.
    kubearmor-dev-next: Setting up libsigsegv2:amd64 (2.13-1ubuntu2) ...
    kubearmor-dev-next: Setting up libfribidi0:amd64 (1.0.8-2ubuntu2) ...
    kubearmor-dev-next: Setting up libpng16-16:amd64 (1.6.37-3build4) ...
    kubearmor-dev-next: Setting up udev (248.3-1ubuntu8) ...
    kubearmor-dev-next: Setting up libss2:amd64 (1.46.3-1ubuntu3) ...
    kubearmor-dev-next: Setting up busybox-initramfs (1:1.30.1-6ubuntu3) ...
    kubearmor-dev-next: Setting up logsave (1.46.3-1ubuntu3) ...
    kubearmor-dev-next: Setting up whiptail (0.52.21-4ubuntu7) ...
    kubearmor-dev-next: Setting up libproc-processtable-perl (0.59-2build2) ...
    kubearmor-dev-next: Setting up dmsetup (2:1.02.175-2.1ubuntu3) ...
    kubearmor-dev-next: update-initramfs: deferring update (trigger activated)
    kubearmor-dev-next: Setting up libplymouth5:amd64 (0.9.5git20210406-0ubuntu2) ...
    kubearmor-dev-next: Setting up libuchardet0:amd64 (0.0.7-1build1) ...
    kubearmor-dev-next: Setting up libeatmydata1:amd64 (105-9build2) ...
    kubearmor-dev-next: Setting up libmpdec3:amd64 (2.5.1-2build1) ...
    kubearmor-dev-next: Setting up libblockdev-part-err2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up libpam-systemd:amd64 (248.3-1ubuntu8) ...
    kubearmor-dev-next: Setting up libefivar1:amd64 (37-6ubuntu2) ...
    kubearmor-dev-next: Setting up libcurl4:amd64 (7.74.0-1.3ubuntu2) ...
    kubearmor-dev-next: Setting up libgirepository-1.0-1:amd64 (1.68.0-1build2) ...
    kubearmor-dev-next: Setting up kbd (2.3.0-3ubuntu3) ...
    kubearmor-dev-next: Setting up curl (7.74.0-1.3ubuntu2) ...
    kubearmor-dev-next: Setting up libvolume-key1 (0.3.12-3.1build2) ...
    kubearmor-dev-next: Setting up linux-headers-5.13.0-20 (5.13.0-20.20) ...
    kubearmor-dev-next: Setting up libaccountsservice0:amd64 (0.6.55-0ubuntu14) ...
    kubearmor-dev-next: Setting up libbinutils:amd64 (2.37-7ubuntu1) ...
    kubearmor-dev-next: Setting up vim-runtime (2:8.2.2434-3ubuntu3) ...
    kubearmor-dev-next: Setting up libfido2-1:amd64 (1.6.0-2build1) ...
    kubearmor-dev-next: Setting up libgcab-1.0-0:amd64 (1.4-3build1) ...
    kubearmor-dev-next: Setting up openssl (1.1.1l-1ubuntu1) ...
    kubearmor-dev-next: Setting up libdrm-common (2.4.107-8ubuntu1) ...
    kubearmor-dev-next: Setting up libelf1:amd64 (0.185-1build1) ...
    kubearmor-dev-next: Setting up libxml2:amd64 (2.9.12+dfsg-4) ...
    kubearmor-dev-next: Setting up tmux (3.1c-1build1) ...
    kubearmor-dev-next: Setting up accountsservice (0.6.55-0ubuntu14) ...
    kubearmor-dev-next: Setting up libudisks2-0:amd64 (2.9.4-1) ...
    kubearmor-dev-next: Setting up libpython3.9-stdlib:amd64 (3.9.7-2build1) ...
    kubearmor-dev-next: Setting up bolt (0.9.1-2) ...
    kubearmor-dev-next: bolt.service is a disabled or a static unit not running, not starting it.
    kubearmor-dev-next: Setting up libpython3-stdlib:amd64 (3.9.4-1build1) ...
    kubearmor-dev-next: Setting up ethtool (1:5.9-1build1) ...
    kubearmor-dev-next: Setting up libctf0:amd64 (2.37-7ubuntu1) ...
    kubearmor-dev-next: Setting up libdw1:amd64 (0.185-1build1) ...
    kubearmor-dev-next: Setting up eatmydata (105-9build2) ...
    kubearmor-dev-next: Setting up libblockdev-crypto2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up irqbalance (1.7.0-1build1) ...
    kubearmor-dev-next: Setting up libblockdev-swap2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up cryptsetup (2:2.3.6-0ubuntu1) ...
    kubearmor-dev-next: Setting up openssh-client (1:8.4p1-6ubuntu2) ...
    kubearmor-dev-next: Setting up ltrace (0.7.3-6.1ubuntu3) ...
    kubearmor-dev-next: Setting up libglib2.0-bin (2.68.4-1ubuntu1) ...
    kubearmor-dev-next: Setting up libblockdev-loop2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up e2fsprogs (1.46.3-1ubuntu3) ...
    kubearmor-dev-next: update-initramfs: deferring update (trigger activated)
    kubearmor-dev-next: e2scrub_all.service is a disabled or a static unit not running, not starting it.
    kubearmor-dev-next: Setting up libcurl3-gnutls:amd64 (7.74.0-1.3ubuntu2) ...
    kubearmor-dev-next: Setting up libefiboot1:amd64 (37-6ubuntu2) ...
    kubearmor-dev-next: Setting up libblockdev2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up vim-tiny (2:8.2.2434-3ubuntu3) ...
    kubearmor-dev-next: Setting up ubuntu-standard (1.472) ...
    kubearmor-dev-next: Setting up libblockdev-part2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up libappstream4:amd64 (0.14.5-1) ...
    kubearmor-dev-next: Setting up grub-common (2.04-1ubuntu47) ...
    kubearmor-dev-next: update-rc.d: warning: start and stop actions are no longer supported; falling back to defaults
    kubearmor-dev-next: Setting up ca-certificates (20210119ubuntu1) ...
    kubearmor-dev-next: Updating certificates in /etc/ssl/certs...
    kubearmor-dev-next: 0 added, 1 removed; done.
    kubearmor-dev-next: Setting up libpython3.9:amd64 (3.9.7-2build1) ...
    kubearmor-dev-next: Setting up cryptsetup-run (2:2.3.6-0ubuntu1) ...
    kubearmor-dev-next: Setting up libpcap0.8:amd64 (1.10.0-2build1) ...
    kubearmor-dev-next: Setting up libblockdev-fs2:amd64 (2.25-2build1) ...
    kubearmor-dev-next: Setting up gir1.2-glib-2.0:amd64 (1.68.0-1build2) ...
    kubearmor-dev-next: Setting up libdrm2:amd64 (2.4.107-8ubuntu1) ...
    kubearmor-dev-next: Setting up groff-base (1.22.4-7) ...
    kubearmor-dev-next: Setting up linux-headers-5.13.0-20-generic (5.13.0-20.20) ...
    kubearmor-dev-next: Setting up libxmlsec1:amd64 (1.2.32-1build1) ...
    kubearmor-dev-next: Setting up cryptsetup-initramfs (2:2.3.6-0ubuntu1) ...
    kubearmor-dev-next: update-initramfs: deferring update (trigger activated)
    kubearmor-dev-next: Setting up libgstreamer1.0-0:amd64 (1.18.5-1) ...
    kubearmor-dev-next: Setcap worked! gst-ptp-helper is not suid!
    kubearmor-dev-next: Setting up python3.9 (3.9.7-2build1) ...
    kubearmor-dev-next: Setting up binutils-x86-64-linux-gnu (2.37-7ubuntu1) ...
    kubearmor-dev-next: Setting up snapd (2.53+21.10ubuntu1) ...
    kubearmor-dev-next: Installing new version of config file /etc/apparmor.d/usr.lib.snapd.snap-confine.real ...
    kubearmor-dev-next: snapd.failure.service is a disabled or a static unit, not starting it.
    kubearmor-dev-next: snapd.snap-repair.service is a disabled or a static unit, not starting it.
    kubearmor-dev-next: Setting up openssh-sftp-server (1:8.4p1-6ubuntu2) ...
    kubearmor-dev-next: Setting up udisks2 (2.9.4-1) ...
    kubearmor-dev-next: Installing new version of config file /etc/udisks2/mount_options.conf.example ...
    kubearmor-dev-next: Setting up vim (2:8.2.2434-3ubuntu3) ...
    kubearmor-dev-next: Setting up openssh-server (1:8.4p1-6ubuntu2) ...
    kubearmor-dev-next: rescue-ssh.target is a disabled or a static unit, not starting it.
    kubearmor-dev-next: Setting up libxmlsec1-openssl:amd64 (1.2.32-1build1) ...
    kubearmor-dev-next: Setting up plymouth (0.9.5git20210406-0ubuntu2) ...
    kubearmor-dev-next: update-initramfs: deferring update (trigger activated)
    kubearmor-dev-next: update-rc.d: warning: start and stop actions are no longer supported; falling back to defaults
    kubearmor-dev-next: update-rc.d: warning: start and stop actions are no longer supported; falling back to defaults
    kubearmor-dev-next: Setting up grub2-common (2.04-1ubuntu47) ...
    kubearmor-dev-next: Setting up python3 (3.9.4-1build1) ...
    kubearmor-dev-next: running python rtupdate hooks for python3.9...
    kubearmor-dev-next: running python post-rtupdate hooks for python3.9...
    kubearmor-dev-next: Setting up linux-headers-generic (5.13.0.20.31) ...
    kubearmor-dev-next: Setting up binutils (2.37-7ubuntu1) ...
    kubearmor-dev-next: Setting up python3-newt:amd64 (0.52.21-4ubuntu7) ...
    kubearmor-dev-next: Setting up grub-pc-bin (2.04-1ubuntu47) ...
    kubearmor-dev-next: Setting up netplan.io (0.103-0ubuntu7) ...
    kubearmor-dev-next: Setting up grub-pc (2.04-1ubuntu47) ...
    kubearmor-dev-next: Sourcing file `/etc/default/grub'
    kubearmor-dev-next: Sourcing file `/etc/default/grub.d/50-cloudimg-settings.cfg'
    kubearmor-dev-next: Sourcing file `/etc/default/grub.d/init-select.cfg'
    kubearmor-dev-next: Generating grub configuration file ...
    kubearmor-dev-next: Found linux image: /boot/vmlinuz-5.13.0-20-generic
    kubearmor-dev-next: Found linux image: /boot/vmlinuz-5.13.0-14-generic
    kubearmor-dev-next: Found initrd image: /boot/initrd.img-5.13.0-14-generic
    kubearmor-dev-next: done
    kubearmor-dev-next: Setting up gir1.2-packagekitglib-1.0 (1.2.2-2ubuntu3) ...
    kubearmor-dev-next: Setting up python3-debian (0.1.39ubuntu1) ...
    kubearmor-dev-next: Setting up python3-gi (3.40.1-1build1) ...
    kubearmor-dev-next: Setting up xfsprogs (5.10.0-4ubuntu2) ...
    kubearmor-dev-next: update-initramfs: deferring update (trigger activated)
    kubearmor-dev-next: Setting up language-selector-common (0.216) ...
    kubearmor-dev-next: Setting up packagekit (1.2.2-2ubuntu3) ...
    kubearmor-dev-next: Setting up lsb-release (11.1.0ubuntu3) ...
    kubearmor-dev-next: Setting up python3-lib2to3 (3.9.7-1) ...
    kubearmor-dev-next: Setting up python3-cffi-backend:amd64 (1.14.6-1build1) ...
    kubearmor-dev-next: Setting up python3-distutils (3.9.7-1) ...
    kubearmor-dev-next: Setting up packagekit-tools (1.2.2-2ubuntu3) ...
    kubearmor-dev-next: Setting up cloud-init (21.3-1-g6803368d-0ubuntu3) ...
    kubearmor-dev-next: Setting up linux-headers-virtual (5.13.0.20.31) ...
    kubearmor-dev-next: Setting up ubuntu-minimal (1.472) ...
    kubearmor-dev-next: Setting up python3-gdbm:amd64 (3.9.7-1) ...
    kubearmor-dev-next: Setting up python3-problem-report (2.20.11-0ubuntu70) ...
    kubearmor-dev-next: Setting up ufw (0.36.1-1) ...
    kubearmor-dev-next: Installing new version of config file /etc/logrotate.d/ufw ...
    kubearmor-dev-next: Setting up python3-distupgrade (1:21.10.8) ...
    kubearmor-dev-next: Setting up landscape-common (19.12-0ubuntu10) ...
    kubearmor-dev-next: Setting up python3-apport (2.20.11-0ubuntu70) ...
    kubearmor-dev-next: Setting up plymouth-theme-ubuntu-text (0.9.5git20210406-0ubuntu2) ...
    kubearmor-dev-next: update-initramfs: deferring update (trigger activated)
    kubearmor-dev-next: Setting up python3-commandnotfound (21.10.0) ...
    kubearmor-dev-next: Setting up ubuntu-release-upgrader-core (1:21.10.8) ...
    kubearmor-dev-next: Setting up open-vm-tools (2:11.3.0-2ubuntu1) ...
    kubearmor-dev-next: Setting up apport (2.20.11-0ubuntu70) ...
    kubearmor-dev-next: Installing new version of config file /etc/apport/crashdb.conf ...
    kubearmor-dev-next: apport-autoreport.service is a disabled or a static unit, not starting it.
    kubearmor-dev-next: Setting up command-not-found (21.10.0) ...
    kubearmor-dev-next: Setting up linux-image-5.13.0-20-generic (5.13.0-20.20) ...
    kubearmor-dev-next: I: /boot/vmlinuz is now a symlink to vmlinuz-5.13.0-20-generic
    kubearmor-dev-next: I: /boot/initrd.img is now a symlink to initrd.img-5.13.0-20-generic
    kubearmor-dev-next: Setting up liblvm2cmd2.03:amd64 (2.03.11-2.1ubuntu3) ...
    kubearmor-dev-next: Setting up linux-modules-5.13.0-20-generic (5.13.0-20.20) ...
    kubearmor-dev-next: Setting up dmeventd (2:1.02.175-2.1ubuntu3) ...
    kubearmor-dev-next: dm-event.service is a disabled or a static unit not running, not starting it.
    kubearmor-dev-next: Setting up linux-image-virtual (5.13.0.20.31) ...
    kubearmor-dev-next: Setting up lvm2 (2.03.11-2.1ubuntu3) ...
    kubearmor-dev-next: update-initramfs: deferring update (trigger activated)
    kubearmor-dev-next: Setting up linux-virtual (5.13.0.20.31) ...
    kubearmor-dev-next: Setting up ubuntu-server (1.472) ...
    kubearmor-dev-next: Processing triggers for install-info (6.7.0.dfsg.2-6) ...
    kubearmor-dev-next: Processing triggers for initramfs-tools (0.140ubuntu6) ...
    kubearmor-dev-next: update-initramfs: Generating /boot/initrd.img-5.13.0-14-generic
    kubearmor-dev-next: Processing triggers for libc-bin (2.34-0ubuntu3) ...
    kubearmor-dev-next: Processing triggers for man-db (2.9.4-2) ...
    kubearmor-dev-next: Processing triggers for ca-certificates (20210119ubuntu1) ...
    kubearmor-dev-next: Updating certificates in /etc/ssl/certs...
    kubearmor-dev-next: 0 added, 0 removed; done.
    kubearmor-dev-next: Running hooks in /etc/ca-certificates/update.d...
    kubearmor-dev-next: done.
    kubearmor-dev-next: Processing triggers for linux-image-5.13.0-20-generic (5.13.0-20.20) ...
    kubearmor-dev-next: /etc/kernel/postinst.d/initramfs-tools:
    kubearmor-dev-next: update-initramfs: Generating /boot/initrd.img-5.13.0-20-generic
    kubearmor-dev-next: /etc/kernel/postinst.d/zz-update-grub:
    kubearmor-dev-next: Sourcing file `/etc/default/grub'
    kubearmor-dev-next: Sourcing file `/etc/default/grub.d/50-cloudimg-settings.cfg'
    kubearmor-dev-next: Sourcing file `/etc/default/grub.d/init-select.cfg'
    kubearmor-dev-next: Generating grub configuration file ...
    kubearmor-dev-next: Found linux image: /boot/vmlinuz-5.13.0-20-generic
    kubearmor-dev-next: Found initrd image: /boot/initrd.img-5.13.0-20-generic
    kubearmor-dev-next: Found linux image: /boot/vmlinuz-5.13.0-14-generic
    kubearmor-dev-next: Found initrd image: /boot/initrd.img-5.13.0-14-generic
    kubearmor-dev-next: done
    kubearmor-dev-next: 
    kubearmor-dev-next: Pending kernel upgrade!
    kubearmor-dev-next: 
    kubearmor-dev-next: Running kernel version:
    kubearmor-dev-next:   5.13.0-14-generic
    kubearmor-dev-next: 
    kubearmor-dev-next: Diagnostics:
    kubearmor-dev-next:   The currently running kernel version is not the expected kernel version 5.13.0-20-generic.
    kubearmor-dev-next: 
    kubearmor-dev-next: Restarting the system to load the new kernel will not be handled automatically, so you should consider rebooting. [Return]
    kubearmor-dev-next: 
    kubearmor-dev-next: Services to be restarted:
    kubearmor-dev-next:  systemctl restart cron.service
    kubearmor-dev-next:  systemctl restart multipathd.service
    kubearmor-dev-next:  systemctl restart polkit.service
    kubearmor-dev-next:  systemctl restart serial-getty@ttyS0.service
    kubearmor-dev-next:  systemctl restart systemd-resolved.service
    kubearmor-dev-next: 
    kubearmor-dev-next: Service restarts being deferred:
    kubearmor-dev-next:  /etc/needrestart/restart.d/dbus.service
    kubearmor-dev-next:  systemctl restart getty@tty1.service
    kubearmor-dev-next:  systemctl restart networkd-dispatcher.service
    kubearmor-dev-next:  systemctl restart systemd-logind.service
    kubearmor-dev-next:  systemctl restart unattended-upgrades.service
    kubearmor-dev-next: 
    kubearmor-dev-next: No containers need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: User sessions running outdated binaries:
    kubearmor-dev-next:  vagrant @ session #3: bash[2165], sshd[1689]
    kubearmor-dev-next:  vagrant @ user manager service: systemd[1366]
==> kubearmor-dev-next: Running provisioner: reload...
==> kubearmor-dev-next: Attempting graceful shutdown of VM...
==> kubearmor-dev-next: Checking if box 'ubuntu/impish64' version '20210904.0.0' is up to date...
==> kubearmor-dev-next: Clearing any previously set forwarded ports...
==> kubearmor-dev-next: Clearing any previously set network interfaces...
==> kubearmor-dev-next: Preparing network interfaces based on configuration...
    kubearmor-dev-next: Adapter 1: nat
==> kubearmor-dev-next: Forwarding ports...
    kubearmor-dev-next: 2345 (guest) => 2346 (host) (adapter 1)
    kubearmor-dev-next: 22 (guest) => 2222 (host) (adapter 1)
==> kubearmor-dev-next: Running 'pre-boot' VM customizations...
==> kubearmor-dev-next: Booting VM...
==> kubearmor-dev-next: Waiting for machine to boot. This may take a few minutes...
==> kubearmor-dev-next: Machine booted and ready!
==> kubearmor-dev-next: Checking for guest additions in VM...
    kubearmor-dev-next: The guest additions on this VM do not match the installed version of
    kubearmor-dev-next: VirtualBox! In most cases this is fine, but in rare cases it can
    kubearmor-dev-next: prevent things such as shared folders from working properly. If you see
    kubearmor-dev-next: shared folder errors, please make sure the guest additions within the
    kubearmor-dev-next: virtual machine match the version of VirtualBox you have installed on
    kubearmor-dev-next: your host and reload your VM.
    kubearmor-dev-next: 
    kubearmor-dev-next: Guest Additions Version: 6.0.0 r127566
    kubearmor-dev-next: VirtualBox Version: 6.1
==> kubearmor-dev-next: Setting hostname...
==> kubearmor-dev-next: Mounting shared folders...
    kubearmor-dev-next: /vagrant => /home/soradji/Desktop/accuknox/KubeArmor/contribution/vagrant
    kubearmor-dev-next: /home/vagrant/KubeArmor => /home/soradji/Desktop/accuknox/KubeArmor
==> kubearmor-dev-next: Machine already provisioned. Run `vagrant provision` or use the `--provision`
==> kubearmor-dev-next: flag to force provisioning. Provisioners marked to run always will still run.
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: inline script
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: /tmp/vagrant-shell20211020-109471-10n5apm.sh
    kubearmor-dev-next: Hit:1 http://archive.ubuntu.com/ubuntu impish InRelease
    kubearmor-dev-next: Hit:2 http://archive.ubuntu.com/ubuntu impish-updates InRelease
    kubearmor-dev-next: Hit:3 http://archive.ubuntu.com/ubuntu impish-backports InRelease
    kubearmor-dev-next: Hit:4 http://security.ubuntu.com/ubuntu impish-security InRelease
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Cloning into 'bcc'...
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: git is already the newest version (1:2.32.0-1ubuntu1).
    kubearmor-dev-next: git set to manually installed.
    kubearmor-dev-next: python3 is already the newest version (3.9.4-1build1).
    kubearmor-dev-next: python3 set to manually installed.
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: The following additional packages will be installed:
    kubearmor-dev-next:   binfmt-support bzip2 cmake-data cpp cpp-11 dpkg-dev fakeroot
    kubearmor-dev-next:   fontconfig-config fonts-dejavu-core g++ g++-11 gcc gcc-10-base gcc-11
    kubearmor-dev-next:   javascript-common lib32gcc-s1 lib32stdc++6 libalgorithm-diff-perl
    kubearmor-dev-next:   libalgorithm-diff-xs-perl libalgorithm-merge-perl libasan6 libatomic1
    kubearmor-dev-next:   libbsd-dev libc-dev-bin libc-devtools libc6-dev libc6-i386 libcc1-0
    kubearmor-dev-next:   libclang-common-9-dev libclang-cpp9 libclang1-9 libcrypt-dev libdeflate0
    kubearmor-dev-next:   libdpkg-perl libexpat1-dev libfakeroot libffi-dev libfile-fcntllock-perl
    kubearmor-dev-next:   libfl2 libfontconfig1 libgc1 libgcc-10-dev libgcc-11-dev libgd3 libgomp1
    kubearmor-dev-next:   libiperf0 libisl23 libitm1 libjbig0 libjpeg-turbo8 libjpeg8 libjs-jquery
    kubearmor-dev-next:   libjs-sphinxdoc libjs-underscore libjsoncpp24 liblsan0 libmd-dev libmpc3
    kubearmor-dev-next:   libncurses-dev libnet1 libnsl-dev libobjc-10-dev libobjc4 libpfm4
    kubearmor-dev-next:   libpython3-dev libpython3.9-dev libquadmath0 librhash0 libsctp1
    kubearmor-dev-next:   libstdc++-10-dev libstdc++-11-dev libtiff5 libtirpc-dev libtsan0 libubsan1
    kubearmor-dev-next:   libwebp6 libxpm4 libz3-4 libz3-dev linux-libc-dev llvm-9 llvm-9-runtime
    kubearmor-dev-next:   llvm-9-tools lto-disabled-list m4 make manpages-dev python-pip-whl
    kubearmor-dev-next:   python3-dev python3-pygments python3-wheel python3.9-dev rpcsvc-proto
    kubearmor-dev-next: Suggested packages:
    kubearmor-dev-next:   bison-doc bzip2-doc clang-9-doc cmake-doc ninja-build cpp-doc gcc-11-locales
    kubearmor-dev-next:   debian-keyring flex-doc g++-multilib g++-11-multilib gcc-11-doc gcc-multilib
    kubearmor-dev-next:   autoconf automake libtool gdb gcc-doc gcc-11-multilib apache2 | lighttpd
    kubearmor-dev-next:   | httpd glibc-doc bzr libgd-tools ncurses-doc lksctp-tools libstdc++-10-doc
    kubearmor-dev-next:   libstdc++-11-doc llvm-9-doc m4-doc make-doc python-pygments-doc
    kubearmor-dev-next:   ttf-bitstream-vera
    kubearmor-dev-next: The following NEW packages will be installed:
    kubearmor-dev-next:   arping binfmt-support bison build-essential bzip2 clang-9 cmake cmake-data
    kubearmor-dev-next:   cpp cpp-11 dpkg-dev fakeroot flex fontconfig-config fonts-dejavu-core g++
    kubearmor-dev-next:   g++-11 gcc gcc-10-base gcc-11 iperf3 javascript-common lib32gcc-s1
    kubearmor-dev-next:   lib32stdc++6 libalgorithm-diff-perl libalgorithm-diff-xs-perl
    kubearmor-dev-next:   libalgorithm-merge-perl libasan6 libatomic1 libbsd-dev libc-dev-bin
    kubearmor-dev-next:   libc-devtools libc6-dev libc6-i386 libcc1-0 libclang-9-dev
    kubearmor-dev-next:   libclang-common-9-dev libclang-cpp9 libclang1-9 libcrypt-dev libdeflate0
    kubearmor-dev-next:   libdpkg-perl libedit-dev libelf-dev libexpat1-dev libfakeroot libffi-dev
    kubearmor-dev-next:   libfile-fcntllock-perl libfl-dev libfl2 libfontconfig1 libgc1 libgcc-10-dev
    kubearmor-dev-next:   libgcc-11-dev libgd3 libgomp1 libiperf0 libisl23 libitm1 libjbig0
    kubearmor-dev-next:   libjpeg-turbo8 libjpeg8 libjs-jquery libjs-sphinxdoc libjs-underscore
    kubearmor-dev-next:   libjsoncpp24 libllvm9 liblsan0 libmd-dev libmpc3 libncurses-dev libnet1
    kubearmor-dev-next:   libnsl-dev libobjc-10-dev libobjc4 libpfm4 libpython3-dev libpython3.9-dev
    kubearmor-dev-next:   libquadmath0 librhash0 libsctp1 libstdc++-10-dev libstdc++-11-dev libtiff5
    kubearmor-dev-next:   libtirpc-dev libtsan0 libubsan1 libwebp6 libxpm4 libz3-4 libz3-dev
    kubearmor-dev-next:   linux-libc-dev llvm-9 llvm-9-dev llvm-9-runtime llvm-9-tools
    kubearmor-dev-next:   lto-disabled-list m4 make manpages-dev netperf python-pip-whl python3-dev
    kubearmor-dev-next:   python3-pip python3-pygments python3-wheel python3.9-dev rpcsvc-proto
    kubearmor-dev-next:   zlib1g-dev
    kubearmor-dev-next: 0 upgraded, 109 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Need to get 307 MB of archives.
    kubearmor-dev-next: After this operation, 1247 MB of additional disk space will be used.
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish/main amd64 m4 amd64 1.4.18-5ubuntu1 [199 kB]
    kubearmor-dev-next: Get:2 http://archive.ubuntu.com/ubuntu impish/main amd64 flex amd64 2.6.4-8build1 [307 kB]
    kubearmor-dev-next: Get:3 http://archive.ubuntu.com/ubuntu impish/main amd64 libnet1 amd64 1.1.6+dfsg-3.1build2 [46.9 kB]
    kubearmor-dev-next: Get:4 http://archive.ubuntu.com/ubuntu impish/universe amd64 arping amd64 2.21-2 [29.2 kB]
    kubearmor-dev-next: Get:5 http://archive.ubuntu.com/ubuntu impish/universe amd64 binfmt-support amd64 2.2.1-1 [53.5 kB]
    kubearmor-dev-next: Get:6 http://archive.ubuntu.com/ubuntu impish/main amd64 bison amd64 2:3.7.6+dfsg-1build1 [727 kB]
    kubearmor-dev-next: Get:7 http://archive.ubuntu.com/ubuntu impish/main amd64 libc-dev-bin amd64 2.34-0ubuntu3 [20.3 kB]
    kubearmor-dev-next: Get:8 http://archive.ubuntu.com/ubuntu impish-updates/main amd64 linux-libc-dev amd64 5.13.0-20.20 [1279 kB]
    kubearmor-dev-next: Get:9 http://archive.ubuntu.com/ubuntu impish/main amd64 libcrypt-dev amd64 1:4.4.18-4ubuntu1 [104 kB]
    kubearmor-dev-next: Get:10 http://archive.ubuntu.com/ubuntu impish/main amd64 rpcsvc-proto amd64 1.4.2-0ubuntu5 [68.4 kB]
    kubearmor-dev-next: Get:11 http://archive.ubuntu.com/ubuntu impish/main amd64 libtirpc-dev amd64 1.3.2-2 [192 kB]
    kubearmor-dev-next: Get:12 http://archive.ubuntu.com/ubuntu impish/main amd64 libnsl-dev amd64 1.3.0-2build1 [71.2 kB]
    kubearmor-dev-next: Get:13 http://archive.ubuntu.com/ubuntu impish/main amd64 libc6-dev amd64 2.34-0ubuntu3 [1886 kB]
    kubearmor-dev-next: Get:14 http://archive.ubuntu.com/ubuntu impish/main amd64 libisl23 amd64 0.24-1 [668 kB]
    kubearmor-dev-next: Get:15 http://archive.ubuntu.com/ubuntu impish/main amd64 libmpc3 amd64 1.2.0-1build1 [44.1 kB]
    kubearmor-dev-next: Get:16 http://archive.ubuntu.com/ubuntu impish/main amd64 cpp-11 amd64 11.2.0-7ubuntu2 [50.6 MB]
    kubearmor-dev-next: Get:17 http://archive.ubuntu.com/ubuntu impish/main amd64 cpp amd64 4:11.2.0-1ubuntu1 [27.7 kB]
    kubearmor-dev-next: Get:18 http://archive.ubuntu.com/ubuntu impish/main amd64 libcc1-0 amd64 11.2.0-7ubuntu2 [53.9 kB]
    kubearmor-dev-next: Get:19 http://archive.ubuntu.com/ubuntu impish/main amd64 libgomp1 amd64 11.2.0-7ubuntu2 [117 kB]
    kubearmor-dev-next: Get:20 http://archive.ubuntu.com/ubuntu impish/main amd64 libitm1 amd64 11.2.0-7ubuntu2 [30.0 kB]
    kubearmor-dev-next: Get:21 http://archive.ubuntu.com/ubuntu impish/main amd64 libatomic1 amd64 11.2.0-7ubuntu2 [10.0 kB]
    kubearmor-dev-next: Get:22 http://archive.ubuntu.com/ubuntu impish/main amd64 libasan6 amd64 11.2.0-7ubuntu2 [2280 kB]
    kubearmor-dev-next: Get:23 http://archive.ubuntu.com/ubuntu impish/main amd64 liblsan0 amd64 11.2.0-7ubuntu2 [974 kB]
    kubearmor-dev-next: Get:24 http://archive.ubuntu.com/ubuntu impish/main amd64 libtsan0 amd64 11.2.0-7ubuntu2 [2259 kB]
    kubearmor-dev-next: Get:25 http://archive.ubuntu.com/ubuntu impish/main amd64 libubsan1 amd64 11.2.0-7ubuntu2 [920 kB]
    kubearmor-dev-next: Get:26 http://archive.ubuntu.com/ubuntu impish/main amd64 libquadmath0 amd64 11.2.0-7ubuntu2 [154 kB]
    kubearmor-dev-next: Get:27 http://archive.ubuntu.com/ubuntu impish/main amd64 libgcc-11-dev amd64 11.2.0-7ubuntu2 [2526 kB]
    kubearmor-dev-next: Get:28 http://archive.ubuntu.com/ubuntu impish/main amd64 gcc-11 amd64 11.2.0-7ubuntu2 [59.3 MB]
    kubearmor-dev-next: Get:29 http://archive.ubuntu.com/ubuntu impish/main amd64 gcc amd64 4:11.2.0-1ubuntu1 [5112 B]
    kubearmor-dev-next: Get:30 http://archive.ubuntu.com/ubuntu impish/main amd64 libstdc++-11-dev amd64 11.2.0-7ubuntu2 [2073 kB]
    kubearmor-dev-next: Get:31 http://archive.ubuntu.com/ubuntu impish/main amd64 g++-11 amd64 11.2.0-7ubuntu2 [55.2 MB]
    kubearmor-dev-next: Get:32 http://archive.ubuntu.com/ubuntu impish/main amd64 g++ amd64 4:11.2.0-1ubuntu1 [1412 B]
    kubearmor-dev-next: Get:33 http://archive.ubuntu.com/ubuntu impish/main amd64 make amd64 4.3-4ubuntu1 [167 kB]
    kubearmor-dev-next: Get:34 http://archive.ubuntu.com/ubuntu impish/main amd64 libdpkg-perl all 1.20.9ubuntu2 [233 kB]
    kubearmor-dev-next: Get:35 http://archive.ubuntu.com/ubuntu impish/main amd64 bzip2 amd64 1.0.8-4ubuntu3 [33.4 kB]
    kubearmor-dev-next: Get:36 http://archive.ubuntu.com/ubuntu impish/main amd64 lto-disabled-list all 16 [12.5 kB]
    kubearmor-dev-next: Get:37 http://archive.ubuntu.com/ubuntu impish/main amd64 dpkg-dev all 1.20.9ubuntu2 [937 kB]
    kubearmor-dev-next: Get:38 http://archive.ubuntu.com/ubuntu impish/main amd64 build-essential amd64 12.9ubuntu2 [4678 B]
    kubearmor-dev-next: Get:39 http://archive.ubuntu.com/ubuntu impish/universe amd64 libllvm9 amd64 1:9.0.1-16.1ubuntu1 [16.4 MB]
    kubearmor-dev-next: Get:40 http://archive.ubuntu.com/ubuntu impish/universe amd64 libclang-cpp9 amd64 1:9.0.1-16.1ubuntu1 [9090 kB]
    kubearmor-dev-next: Get:41 http://archive.ubuntu.com/ubuntu impish/main amd64 gcc-10-base amd64 10.3.0-11ubuntu1 [20.7 kB]
    kubearmor-dev-next: Get:42 http://archive.ubuntu.com/ubuntu impish/main amd64 libgcc-10-dev amd64 10.3.0-11ubuntu1 [2490 kB]
    kubearmor-dev-next: Get:43 http://archive.ubuntu.com/ubuntu impish/main amd64 libstdc++-10-dev amd64 10.3.0-11ubuntu1 [1863 kB]
    kubearmor-dev-next: Get:44 http://archive.ubuntu.com/ubuntu impish/main amd64 libgc1 amd64 1:8.0.4-3 [88.4 kB]
    kubearmor-dev-next: Get:45 http://archive.ubuntu.com/ubuntu impish/universe amd64 libobjc4 amd64 11.2.0-7ubuntu2 [49.0 kB]
    kubearmor-dev-next: Get:46 http://archive.ubuntu.com/ubuntu impish/universe amd64 libobjc-10-dev amd64 10.3.0-11ubuntu1 [195 kB]
    kubearmor-dev-next: Get:47 http://archive.ubuntu.com/ubuntu impish/main amd64 libc6-i386 amd64 2.34-0ubuntu3 [2819 kB]
    kubearmor-dev-next: Get:48 http://archive.ubuntu.com/ubuntu impish/main amd64 lib32gcc-s1 amd64 11.2.0-7ubuntu2 [54.3 kB]
    kubearmor-dev-next: Get:49 http://archive.ubuntu.com/ubuntu impish/main amd64 lib32stdc++6 amd64 11.2.0-7ubuntu2 [691 kB]
    kubearmor-dev-next: Get:50 http://archive.ubuntu.com/ubuntu impish/universe amd64 libclang-common-9-dev amd64 1:9.0.1-16.1ubuntu1 [3621 kB]
    kubearmor-dev-next: Get:51 http://archive.ubuntu.com/ubuntu impish/universe amd64 clang-9 amd64 1:9.0.1-16.1ubuntu1 [1222 kB]
    kubearmor-dev-next: Get:52 http://archive.ubuntu.com/ubuntu impish/main amd64 cmake-data all 3.18.4-2ubuntu2 [1728 kB]
    kubearmor-dev-next: Get:53 http://archive.ubuntu.com/ubuntu impish/main amd64 libjsoncpp24 amd64 1.9.4-4build1 [80.3 kB]
    kubearmor-dev-next: Get:54 http://archive.ubuntu.com/ubuntu impish/main amd64 librhash0 amd64 1.4.1-2build1 [124 kB]
    kubearmor-dev-next: Get:55 http://archive.ubuntu.com/ubuntu impish/main amd64 cmake amd64 3.18.4-2ubuntu2 [4435 kB]
    kubearmor-dev-next: Get:56 http://archive.ubuntu.com/ubuntu impish/main amd64 libfakeroot amd64 1.25.3-1.1ubuntu2 [28.1 kB]
    kubearmor-dev-next: Get:57 http://archive.ubuntu.com/ubuntu impish/main amd64 fakeroot amd64 1.25.3-1.1ubuntu2 [62.9 kB]
    kubearmor-dev-next: Get:58 http://archive.ubuntu.com/ubuntu impish/main amd64 fonts-dejavu-core all 2.37-2build1 [1041 kB]
    kubearmor-dev-next: Get:59 http://archive.ubuntu.com/ubuntu impish/main amd64 fontconfig-config all 2.13.1-4.2ubuntu3 [28.2 kB]
    kubearmor-dev-next: Get:60 http://archive.ubuntu.com/ubuntu impish/main amd64 libsctp1 amd64 1.0.19+dfsg-1 [9374 B]
    kubearmor-dev-next: Get:61 http://archive.ubuntu.com/ubuntu impish/universe amd64 libiperf0 amd64 3.9-1 [75.4 kB]
    kubearmor-dev-next: Get:62 http://archive.ubuntu.com/ubuntu impish/universe amd64 iperf3 amd64 3.9-1 [14.3 kB]
    kubearmor-dev-next: Get:63 http://archive.ubuntu.com/ubuntu impish/main amd64 javascript-common all 11+nmu1 [5936 B]
    kubearmor-dev-next: Get:64 http://archive.ubuntu.com/ubuntu impish/main amd64 libalgorithm-diff-perl all 1.201-1 [41.8 kB]
    kubearmor-dev-next: Get:65 http://archive.ubuntu.com/ubuntu impish/main amd64 libalgorithm-diff-xs-perl amd64 0.04-6build1 [11.4 kB]
    kubearmor-dev-next: Get:66 http://archive.ubuntu.com/ubuntu impish/main amd64 libalgorithm-merge-perl all 0.08-3 [12.0 kB]
    kubearmor-dev-next: Get:67 http://archive.ubuntu.com/ubuntu impish/main amd64 libmd-dev amd64 1.0.3-3build1 [38.4 kB]
    kubearmor-dev-next: Get:68 http://archive.ubuntu.com/ubuntu impish/main amd64 libbsd-dev amd64 0.11.3-1ubuntu2 [165 kB]
    kubearmor-dev-next: Get:69 http://archive.ubuntu.com/ubuntu impish/main amd64 libfontconfig1 amd64 2.13.1-4.2ubuntu3 [116 kB]
    kubearmor-dev-next: Get:70 http://archive.ubuntu.com/ubuntu impish/main amd64 libjpeg-turbo8 amd64 2.0.6-0ubuntu2 [117 kB]
    kubearmor-dev-next: Get:71 http://archive.ubuntu.com/ubuntu impish/main amd64 libjpeg8 amd64 8c-2ubuntu8 [2194 B]
    kubearmor-dev-next: Get:72 http://archive.ubuntu.com/ubuntu impish/main amd64 libdeflate0 amd64 1.7-2ubuntu2 [56.3 kB]
    kubearmor-dev-next: Get:73 http://archive.ubuntu.com/ubuntu impish/main amd64 libjbig0 amd64 2.1-3.1build1 [26.7 kB]
    kubearmor-dev-next: Get:74 http://archive.ubuntu.com/ubuntu impish/main amd64 libwebp6 amd64 0.6.1-2.1 [183 kB]
    kubearmor-dev-next: Get:75 http://archive.ubuntu.com/ubuntu impish/main amd64 libtiff5 amd64 4.3.0-1 [168 kB]
    kubearmor-dev-next: Get:76 http://archive.ubuntu.com/ubuntu impish/main amd64 libxpm4 amd64 1:3.5.12-1 [34.0 kB]
    kubearmor-dev-next: Get:77 http://archive.ubuntu.com/ubuntu impish/main amd64 libgd3 amd64 2.3.0-2ubuntu1 [129 kB]
    kubearmor-dev-next: Get:78 http://archive.ubuntu.com/ubuntu impish/main amd64 libc-devtools amd64 2.34-0ubuntu3 [28.7 kB]
    kubearmor-dev-next: Get:79 http://archive.ubuntu.com/ubuntu impish/universe amd64 libclang1-9 amd64 1:9.0.1-16.1ubuntu1 [7301 kB]
    kubearmor-dev-next: Get:80 http://archive.ubuntu.com/ubuntu impish/universe amd64 libclang-9-dev amd64 1:9.0.1-16.1ubuntu1 [17.4 MB]
    kubearmor-dev-next: Get:81 http://archive.ubuntu.com/ubuntu impish/main amd64 libncurses-dev amd64 6.2+20201114-2build1 [344 kB]
    kubearmor-dev-next: Get:82 http://archive.ubuntu.com/ubuntu impish/main amd64 libedit-dev amd64 3.1-20191231-2build1 [117 kB]
    kubearmor-dev-next: Get:83 http://archive.ubuntu.com/ubuntu impish/main amd64 zlib1g-dev amd64 1:1.2.11.dfsg-2ubuntu7 [164 kB]
    kubearmor-dev-next: Get:84 http://archive.ubuntu.com/ubuntu impish/main amd64 libelf-dev amd64 0.185-1build1 [64.3 kB]
    kubearmor-dev-next: Get:85 http://archive.ubuntu.com/ubuntu impish/main amd64 libexpat1-dev amd64 2.4.1-2 [147 kB]
    kubearmor-dev-next: Get:86 http://archive.ubuntu.com/ubuntu impish/main amd64 libfile-fcntllock-perl amd64 0.22-3build5 [33.1 kB]
    kubearmor-dev-next: Get:87 http://archive.ubuntu.com/ubuntu impish/main amd64 libfl2 amd64 2.6.4-8build1 [10.8 kB]
    kubearmor-dev-next: Get:88 http://archive.ubuntu.com/ubuntu impish/main amd64 libfl-dev amd64 2.6.4-8build1 [6238 B]
    kubearmor-dev-next: Get:89 http://archive.ubuntu.com/ubuntu impish/main amd64 libjs-jquery all 3.5.1+dfsg+~3.5.5-7 [314 kB]
    kubearmor-dev-next: Get:90 http://archive.ubuntu.com/ubuntu impish/main amd64 libjs-underscore all 1.9.1~dfsg-3 [99.3 kB]
    kubearmor-dev-next: Get:91 http://archive.ubuntu.com/ubuntu impish/main amd64 libjs-sphinxdoc all 3.5.4-2 [131 kB]
    kubearmor-dev-next: Get:92 http://archive.ubuntu.com/ubuntu impish/main amd64 libpython3.9-dev amd64 3.9.7-2build1 [4600 kB]
    kubearmor-dev-next: Get:93 http://archive.ubuntu.com/ubuntu impish/main amd64 libpython3-dev amd64 3.9.4-1build1 [7402 B]
    kubearmor-dev-next: Get:94 http://archive.ubuntu.com/ubuntu impish/universe amd64 llvm-9-runtime amd64 1:9.0.1-16.1ubuntu1 [196 kB]
    kubearmor-dev-next: Get:95 http://archive.ubuntu.com/ubuntu impish/universe amd64 libpfm4 amd64 4.11.1+git32-gd0b85fb-1 [278 kB]
    kubearmor-dev-next: Get:96 http://archive.ubuntu.com/ubuntu impish/universe amd64 llvm-9 amd64 1:9.0.1-16.1ubuntu1 [5240 kB]
    kubearmor-dev-next: Get:97 http://archive.ubuntu.com/ubuntu impish/main amd64 libffi-dev amd64 3.4.2-1ubuntu5 [61.7 kB]
    kubearmor-dev-next: Get:98 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-pygments all 2.7.1+dfsg-2.1 [639 kB]
    kubearmor-dev-next: Get:99 http://archive.ubuntu.com/ubuntu impish/universe amd64 llvm-9-tools amd64 1:9.0.1-16.1ubuntu1 [319 kB]
    kubearmor-dev-next: Get:100 http://archive.ubuntu.com/ubuntu impish/universe amd64 libz3-4 amd64 4.8.12-1 [5766 kB]
    kubearmor-dev-next: Get:101 http://archive.ubuntu.com/ubuntu impish/universe amd64 libz3-dev amd64 4.8.12-1 [72.2 kB]
    kubearmor-dev-next: Get:102 http://archive.ubuntu.com/ubuntu impish/universe amd64 llvm-9-dev amd64 1:9.0.1-16.1ubuntu1 [27.1 MB]
    kubearmor-dev-next: Get:103 http://archive.ubuntu.com/ubuntu impish/main amd64 manpages-dev all 5.10-1ubuntu1 [2309 kB]
    kubearmor-dev-next: Get:104 http://archive.ubuntu.com/ubuntu impish/multiverse amd64 netperf amd64 2.7.0-0.1 [540 kB]
    kubearmor-dev-next: Get:105 http://archive.ubuntu.com/ubuntu impish/universe amd64 python-pip-whl all 20.3.4-4 [1897 kB]
    kubearmor-dev-next: Get:106 http://archive.ubuntu.com/ubuntu impish/main amd64 python3.9-dev amd64 3.9.7-2build1 [507 kB]
    kubearmor-dev-next: Get:107 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-dev amd64 3.9.4-1build1 [25.5 kB]
    kubearmor-dev-next: Get:108 http://archive.ubuntu.com/ubuntu impish/universe amd64 python3-wheel all 0.34.2-1 [23.8 kB]
    kubearmor-dev-next: Get:109 http://archive.ubuntu.com/ubuntu impish/universe amd64 python3-pip all 20.3.4-4 [283 kB]
    kubearmor-dev-next: dpkg-preconfigure: unable to re-open stdin: No such file or directory
    kubearmor-dev-next: Fetched 307 MB in 3min 35s (1425 kB/s)
    kubearmor-dev-next: Selecting previously unselected package m4.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 91285 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../000-m4_1.4.18-5ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking m4 (1.4.18-5ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package flex.
    kubearmor-dev-next: Preparing to unpack .../001-flex_2.6.4-8build1_amd64.deb ...
    kubearmor-dev-next: Unpacking flex (2.6.4-8build1) ...
    kubearmor-dev-next: Selecting previously unselected package libnet1:amd64.
    kubearmor-dev-next: Preparing to unpack .../002-libnet1_1.1.6+dfsg-3.1build2_amd64.deb ...
    kubearmor-dev-next: Unpacking libnet1:amd64 (1.1.6+dfsg-3.1build2) ...
    kubearmor-dev-next: Selecting previously unselected package arping.
    kubearmor-dev-next: Preparing to unpack .../003-arping_2.21-2_amd64.deb ...
    kubearmor-dev-next: Unpacking arping (2.21-2) ...
    kubearmor-dev-next: Selecting previously unselected package binfmt-support.
    kubearmor-dev-next: Preparing to unpack .../004-binfmt-support_2.2.1-1_amd64.deb ...
    kubearmor-dev-next: Unpacking binfmt-support (2.2.1-1) ...
    kubearmor-dev-next: Selecting previously unselected package bison.
    kubearmor-dev-next: Preparing to unpack .../005-bison_2%3a3.7.6+dfsg-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking bison (2:3.7.6+dfsg-1build1) ...
    kubearmor-dev-next: Selecting previously unselected package libc-dev-bin.
    kubearmor-dev-next: Preparing to unpack .../006-libc-dev-bin_2.34-0ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libc-dev-bin (2.34-0ubuntu3) ...
    kubearmor-dev-next: Selecting previously unselected package linux-libc-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../007-linux-libc-dev_5.13.0-20.20_amd64.deb ...
    kubearmor-dev-next: Unpacking linux-libc-dev:amd64 (5.13.0-20.20) ...
    kubearmor-dev-next: Selecting previously unselected package libcrypt-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../008-libcrypt-dev_1%3a4.4.18-4ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libcrypt-dev:amd64 (1:4.4.18-4ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package rpcsvc-proto.
    kubearmor-dev-next: Preparing to unpack .../009-rpcsvc-proto_1.4.2-0ubuntu5_amd64.deb ...
    kubearmor-dev-next: Unpacking rpcsvc-proto (1.4.2-0ubuntu5) ...
    kubearmor-dev-next: Selecting previously unselected package libtirpc-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../010-libtirpc-dev_1.3.2-2_amd64.deb ...
    kubearmor-dev-next: Unpacking libtirpc-dev:amd64 (1.3.2-2) ...
    kubearmor-dev-next: Selecting previously unselected package libnsl-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../011-libnsl-dev_1.3.0-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libnsl-dev:amd64 (1.3.0-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package libc6-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../012-libc6-dev_2.34-0ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libc6-dev:amd64 (2.34-0ubuntu3) ...
    kubearmor-dev-next: Selecting previously unselected package libisl23:amd64.
    kubearmor-dev-next: Preparing to unpack .../013-libisl23_0.24-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libisl23:amd64 (0.24-1) ...
    kubearmor-dev-next: Selecting previously unselected package libmpc3:amd64.
    kubearmor-dev-next: Preparing to unpack .../014-libmpc3_1.2.0-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libmpc3:amd64 (1.2.0-1build1) ...
    kubearmor-dev-next: Selecting previously unselected package cpp-11.
    kubearmor-dev-next: Preparing to unpack .../015-cpp-11_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking cpp-11 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package cpp.
    kubearmor-dev-next: Preparing to unpack .../016-cpp_4%3a11.2.0-1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking cpp (4:11.2.0-1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libcc1-0:amd64.
    kubearmor-dev-next: Preparing to unpack .../017-libcc1-0_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libcc1-0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libgomp1:amd64.
    kubearmor-dev-next: Preparing to unpack .../018-libgomp1_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libgomp1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libitm1:amd64.
    kubearmor-dev-next: Preparing to unpack .../019-libitm1_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libitm1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libatomic1:amd64.
    kubearmor-dev-next: Preparing to unpack .../020-libatomic1_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libatomic1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libasan6:amd64.
    kubearmor-dev-next: Preparing to unpack .../021-libasan6_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libasan6:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package liblsan0:amd64.
    kubearmor-dev-next: Preparing to unpack .../022-liblsan0_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking liblsan0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libtsan0:amd64.
    kubearmor-dev-next: Preparing to unpack .../023-libtsan0_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libtsan0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libubsan1:amd64.
    kubearmor-dev-next: Preparing to unpack .../024-libubsan1_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libubsan1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libquadmath0:amd64.
    kubearmor-dev-next: Preparing to unpack .../025-libquadmath0_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libquadmath0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libgcc-11-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../026-libgcc-11-dev_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libgcc-11-dev:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package gcc-11.
    kubearmor-dev-next: Preparing to unpack .../027-gcc-11_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking gcc-11 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package gcc.
    kubearmor-dev-next: Preparing to unpack .../028-gcc_4%3a11.2.0-1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking gcc (4:11.2.0-1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libstdc++-11-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../029-libstdc++-11-dev_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libstdc++-11-dev:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package g++-11.
    kubearmor-dev-next: Preparing to unpack .../030-g++-11_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking g++-11 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package g++.
    kubearmor-dev-next: Preparing to unpack .../031-g++_4%3a11.2.0-1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking g++ (4:11.2.0-1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package make.
    kubearmor-dev-next: Preparing to unpack .../032-make_4.3-4ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking make (4.3-4ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libdpkg-perl.
    kubearmor-dev-next: Preparing to unpack .../033-libdpkg-perl_1.20.9ubuntu2_all.deb ...
    kubearmor-dev-next: Unpacking libdpkg-perl (1.20.9ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package bzip2.
    kubearmor-dev-next: Preparing to unpack .../034-bzip2_1.0.8-4ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking bzip2 (1.0.8-4ubuntu3) ...
    kubearmor-dev-next: Selecting previously unselected package lto-disabled-list.
    kubearmor-dev-next: Preparing to unpack .../035-lto-disabled-list_16_all.deb ...
    kubearmor-dev-next: Unpacking lto-disabled-list (16) ...
    kubearmor-dev-next: Selecting previously unselected package dpkg-dev.
    kubearmor-dev-next: Preparing to unpack .../036-dpkg-dev_1.20.9ubuntu2_all.deb ...
    kubearmor-dev-next: Unpacking dpkg-dev (1.20.9ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package build-essential.
    kubearmor-dev-next: Preparing to unpack .../037-build-essential_12.9ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking build-essential (12.9ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libllvm9:amd64.
    kubearmor-dev-next: Preparing to unpack .../038-libllvm9_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libllvm9:amd64 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libclang-cpp9.
    kubearmor-dev-next: Preparing to unpack .../039-libclang-cpp9_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libclang-cpp9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package gcc-10-base:amd64.
    kubearmor-dev-next: Preparing to unpack .../040-gcc-10-base_10.3.0-11ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking gcc-10-base:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libgcc-10-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../041-libgcc-10-dev_10.3.0-11ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libgcc-10-dev:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libstdc++-10-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../042-libstdc++-10-dev_10.3.0-11ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libstdc++-10-dev:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libgc1:amd64.
    kubearmor-dev-next: Preparing to unpack .../043-libgc1_1%3a8.0.4-3_amd64.deb ...
    kubearmor-dev-next: Unpacking libgc1:amd64 (1:8.0.4-3) ...
    kubearmor-dev-next: Selecting previously unselected package libobjc4:amd64.
    kubearmor-dev-next: Preparing to unpack .../044-libobjc4_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libobjc4:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libobjc-10-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../045-libobjc-10-dev_10.3.0-11ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libobjc-10-dev:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libc6-i386.
    kubearmor-dev-next: Preparing to unpack .../046-libc6-i386_2.34-0ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libc6-i386 (2.34-0ubuntu3) ...
    kubearmor-dev-next: Selecting previously unselected package lib32gcc-s1.
    kubearmor-dev-next: Preparing to unpack .../047-lib32gcc-s1_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking lib32gcc-s1 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package lib32stdc++6.
    kubearmor-dev-next: Preparing to unpack .../048-lib32stdc++6_11.2.0-7ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking lib32stdc++6 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libclang-common-9-dev.
    kubearmor-dev-next: Preparing to unpack .../049-libclang-common-9-dev_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libclang-common-9-dev (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package clang-9.
    kubearmor-dev-next: Preparing to unpack .../050-clang-9_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking clang-9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package cmake-data.
    kubearmor-dev-next: Preparing to unpack .../051-cmake-data_3.18.4-2ubuntu2_all.deb ...
    kubearmor-dev-next: Unpacking cmake-data (3.18.4-2ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libjsoncpp24:amd64.
    kubearmor-dev-next: Preparing to unpack .../052-libjsoncpp24_1.9.4-4build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libjsoncpp24:amd64 (1.9.4-4build1) ...
    kubearmor-dev-next: Selecting previously unselected package librhash0:amd64.
    kubearmor-dev-next: Preparing to unpack .../053-librhash0_1.4.1-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking librhash0:amd64 (1.4.1-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package cmake.
    kubearmor-dev-next: Preparing to unpack .../054-cmake_3.18.4-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking cmake (3.18.4-2ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libfakeroot:amd64.
    kubearmor-dev-next: Preparing to unpack .../055-libfakeroot_1.25.3-1.1ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libfakeroot:amd64 (1.25.3-1.1ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package fakeroot.
    kubearmor-dev-next: Preparing to unpack .../056-fakeroot_1.25.3-1.1ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking fakeroot (1.25.3-1.1ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package fonts-dejavu-core.
    kubearmor-dev-next: Preparing to unpack .../057-fonts-dejavu-core_2.37-2build1_all.deb ...
    kubearmor-dev-next: Unpacking fonts-dejavu-core (2.37-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package fontconfig-config.
    kubearmor-dev-next: Preparing to unpack .../058-fontconfig-config_2.13.1-4.2ubuntu3_all.deb ...
    kubearmor-dev-next: Unpacking fontconfig-config (2.13.1-4.2ubuntu3) ...
    kubearmor-dev-next: Selecting previously unselected package libsctp1:amd64.
    kubearmor-dev-next: Preparing to unpack .../059-libsctp1_1.0.19+dfsg-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libsctp1:amd64 (1.0.19+dfsg-1) ...
    kubearmor-dev-next: Selecting previously unselected package libiperf0:amd64.
    kubearmor-dev-next: Preparing to unpack .../060-libiperf0_3.9-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libiperf0:amd64 (3.9-1) ...
    kubearmor-dev-next: Selecting previously unselected package iperf3.
    kubearmor-dev-next: Preparing to unpack .../061-iperf3_3.9-1_amd64.deb ...
    kubearmor-dev-next: Unpacking iperf3 (3.9-1) ...
    kubearmor-dev-next: Selecting previously unselected package javascript-common.
    kubearmor-dev-next: Preparing to unpack .../062-javascript-common_11+nmu1_all.deb ...
    kubearmor-dev-next: Unpacking javascript-common (11+nmu1) ...
    kubearmor-dev-next: Selecting previously unselected package libalgorithm-diff-perl.
    kubearmor-dev-next: Preparing to unpack .../063-libalgorithm-diff-perl_1.201-1_all.deb ...
    kubearmor-dev-next: Unpacking libalgorithm-diff-perl (1.201-1) ...
    kubearmor-dev-next: Selecting previously unselected package libalgorithm-diff-xs-perl.
    kubearmor-dev-next: Preparing to unpack .../064-libalgorithm-diff-xs-perl_0.04-6build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libalgorithm-diff-xs-perl (0.04-6build1) ...
    kubearmor-dev-next: Selecting previously unselected package libalgorithm-merge-perl.
    kubearmor-dev-next: Preparing to unpack .../065-libalgorithm-merge-perl_0.08-3_all.deb ...
    kubearmor-dev-next: Unpacking libalgorithm-merge-perl (0.08-3) ...
    kubearmor-dev-next: Selecting previously unselected package libmd-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../066-libmd-dev_1.0.3-3build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libmd-dev:amd64 (1.0.3-3build1) ...
    kubearmor-dev-next: Selecting previously unselected package libbsd-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../067-libbsd-dev_0.11.3-1ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libbsd-dev:amd64 (0.11.3-1ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libfontconfig1:amd64.
    kubearmor-dev-next: Preparing to unpack .../068-libfontconfig1_2.13.1-4.2ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libfontconfig1:amd64 (2.13.1-4.2ubuntu3) ...
    kubearmor-dev-next: Selecting previously unselected package libjpeg-turbo8:amd64.
    kubearmor-dev-next: Preparing to unpack .../069-libjpeg-turbo8_2.0.6-0ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libjpeg-turbo8:amd64 (2.0.6-0ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libjpeg8:amd64.
    kubearmor-dev-next: Preparing to unpack .../070-libjpeg8_8c-2ubuntu8_amd64.deb ...
    kubearmor-dev-next: Unpacking libjpeg8:amd64 (8c-2ubuntu8) ...
    kubearmor-dev-next: Selecting previously unselected package libdeflate0:amd64.
    kubearmor-dev-next: Preparing to unpack .../071-libdeflate0_1.7-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libdeflate0:amd64 (1.7-2ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package libjbig0:amd64.
    kubearmor-dev-next: Preparing to unpack .../072-libjbig0_2.1-3.1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libjbig0:amd64 (2.1-3.1build1) ...
    kubearmor-dev-next: Selecting previously unselected package libwebp6:amd64.
    kubearmor-dev-next: Preparing to unpack .../073-libwebp6_0.6.1-2.1_amd64.deb ...
    kubearmor-dev-next: Unpacking libwebp6:amd64 (0.6.1-2.1) ...
    kubearmor-dev-next: Selecting previously unselected package libtiff5:amd64.
    kubearmor-dev-next: Preparing to unpack .../074-libtiff5_4.3.0-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libtiff5:amd64 (4.3.0-1) ...
    kubearmor-dev-next: Selecting previously unselected package libxpm4:amd64.
    kubearmor-dev-next: Preparing to unpack .../075-libxpm4_1%3a3.5.12-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libxpm4:amd64 (1:3.5.12-1) ...
    kubearmor-dev-next: Selecting previously unselected package libgd3:amd64.
    kubearmor-dev-next: Preparing to unpack .../076-libgd3_2.3.0-2ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libgd3:amd64 (2.3.0-2ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libc-devtools.
    kubearmor-dev-next: Preparing to unpack .../077-libc-devtools_2.34-0ubuntu3_amd64.deb ...
    kubearmor-dev-next: Unpacking libc-devtools (2.34-0ubuntu3) ...
    kubearmor-dev-next: Selecting previously unselected package libclang1-9.
    kubearmor-dev-next: Preparing to unpack .../078-libclang1-9_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libclang1-9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libclang-9-dev.
    kubearmor-dev-next: Preparing to unpack .../079-libclang-9-dev_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking libclang-9-dev (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libncurses-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../080-libncurses-dev_6.2+20201114-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libncurses-dev:amd64 (6.2+20201114-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package libedit-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../081-libedit-dev_3.1-20191231-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libedit-dev:amd64 (3.1-20191231-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package zlib1g-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../082-zlib1g-dev_1%3a1.2.11.dfsg-2ubuntu7_amd64.deb ...
    kubearmor-dev-next: Unpacking zlib1g-dev:amd64 (1:1.2.11.dfsg-2ubuntu7) ...
    kubearmor-dev-next: Selecting previously unselected package libelf-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../083-libelf-dev_0.185-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libelf-dev:amd64 (0.185-1build1) ...
    kubearmor-dev-next: Selecting previously unselected package libexpat1-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../084-libexpat1-dev_2.4.1-2_amd64.deb ...
    kubearmor-dev-next: Unpacking libexpat1-dev:amd64 (2.4.1-2) ...
    kubearmor-dev-next: Selecting previously unselected package libfile-fcntllock-perl.
    kubearmor-dev-next: Preparing to unpack .../085-libfile-fcntllock-perl_0.22-3build5_amd64.deb ...
    kubearmor-dev-next: Unpacking libfile-fcntllock-perl (0.22-3build5) ...
    kubearmor-dev-next: Selecting previously unselected package libfl2:amd64.
    kubearmor-dev-next: Preparing to unpack .../086-libfl2_2.6.4-8build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libfl2:amd64 (2.6.4-8build1) ...
    kubearmor-dev-next: Selecting previously unselected package libfl-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../087-libfl-dev_2.6.4-8build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libfl-dev:amd64 (2.6.4-8build1) ...
    kubearmor-dev-next: Selecting previously unselected package libjs-jquery.
    kubearmor-dev-next: Preparing to unpack .../088-libjs-jquery_3.5.1+dfsg+~3.5.5-7_all.deb ...
    kubearmor-dev-next: Unpacking libjs-jquery (3.5.1+dfsg+~3.5.5-7) ...
    kubearmor-dev-next: Selecting previously unselected package libjs-underscore.
    kubearmor-dev-next: Preparing to unpack .../089-libjs-underscore_1.9.1~dfsg-3_all.deb ...
    kubearmor-dev-next: Unpacking libjs-underscore (1.9.1~dfsg-3) ...
    kubearmor-dev-next: Selecting previously unselected package libjs-sphinxdoc.
    kubearmor-dev-next: Preparing to unpack .../090-libjs-sphinxdoc_3.5.4-2_all.deb ...
    kubearmor-dev-next: Unpacking libjs-sphinxdoc (3.5.4-2) ...
    kubearmor-dev-next: Selecting previously unselected package libpython3.9-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../091-libpython3.9-dev_3.9.7-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpython3.9-dev:amd64 (3.9.7-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package libpython3-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../092-libpython3-dev_3.9.4-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpython3-dev:amd64 (3.9.4-1build1) ...
    kubearmor-dev-next: Selecting previously unselected package llvm-9-runtime.
    kubearmor-dev-next: Preparing to unpack .../093-llvm-9-runtime_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking llvm-9-runtime (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libpfm4:amd64.
    kubearmor-dev-next: Preparing to unpack .../094-libpfm4_4.11.1+git32-gd0b85fb-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libpfm4:amd64 (4.11.1+git32-gd0b85fb-1) ...
    kubearmor-dev-next: Selecting previously unselected package llvm-9.
    kubearmor-dev-next: Preparing to unpack .../095-llvm-9_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking llvm-9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libffi-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../096-libffi-dev_3.4.2-1ubuntu5_amd64.deb ...
    kubearmor-dev-next: Unpacking libffi-dev:amd64 (3.4.2-1ubuntu5) ...
    kubearmor-dev-next: Selecting previously unselected package python3-pygments.
    kubearmor-dev-next: Preparing to unpack .../097-python3-pygments_2.7.1+dfsg-2.1_all.deb ...
    kubearmor-dev-next: Unpacking python3-pygments (2.7.1+dfsg-2.1) ...
    kubearmor-dev-next: Selecting previously unselected package llvm-9-tools.
    kubearmor-dev-next: Preparing to unpack .../098-llvm-9-tools_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking llvm-9-tools (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package libz3-4:amd64.
    kubearmor-dev-next: Preparing to unpack .../099-libz3-4_4.8.12-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libz3-4:amd64 (4.8.12-1) ...
    kubearmor-dev-next: Selecting previously unselected package libz3-dev:amd64.
    kubearmor-dev-next: Preparing to unpack .../100-libz3-dev_4.8.12-1_amd64.deb ...
    kubearmor-dev-next: Unpacking libz3-dev:amd64 (4.8.12-1) ...
    kubearmor-dev-next: Selecting previously unselected package llvm-9-dev.
    kubearmor-dev-next: Preparing to unpack .../101-llvm-9-dev_1%3a9.0.1-16.1ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking llvm-9-dev (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package manpages-dev.
    kubearmor-dev-next: Preparing to unpack .../102-manpages-dev_5.10-1ubuntu1_all.deb ...
    kubearmor-dev-next: Unpacking manpages-dev (5.10-1ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package netperf.
    kubearmor-dev-next: Preparing to unpack .../103-netperf_2.7.0-0.1_amd64.deb ...
    kubearmor-dev-next: Unpacking netperf (2.7.0-0.1) ...
    kubearmor-dev-next: Selecting previously unselected package python-pip-whl.
    kubearmor-dev-next: Preparing to unpack .../104-python-pip-whl_20.3.4-4_all.deb ...
    kubearmor-dev-next: Unpacking python-pip-whl (20.3.4-4) ...
    kubearmor-dev-next: Selecting previously unselected package python3.9-dev.
    kubearmor-dev-next: Preparing to unpack .../105-python3.9-dev_3.9.7-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3.9-dev (3.9.7-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package python3-dev.
    kubearmor-dev-next: Preparing to unpack .../106-python3-dev_3.9.4-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-dev (3.9.4-1build1) ...
    kubearmor-dev-next: Selecting previously unselected package python3-wheel.
    kubearmor-dev-next: Preparing to unpack .../107-python3-wheel_0.34.2-1_all.deb ...
    kubearmor-dev-next: Unpacking python3-wheel (0.34.2-1) ...
    kubearmor-dev-next: Selecting previously unselected package python3-pip.
    kubearmor-dev-next: Preparing to unpack .../108-python3-pip_20.3.4-4_all.deb ...
    kubearmor-dev-next: Unpacking python3-pip (20.3.4-4) ...
    kubearmor-dev-next: Setting up javascript-common (11+nmu1) ...
    kubearmor-dev-next: Setting up manpages-dev (5.10-1ubuntu1) ...
    kubearmor-dev-next: Setting up lto-disabled-list (16) ...
    kubearmor-dev-next: Setting up libxpm4:amd64 (1:3.5.12-1) ...
    kubearmor-dev-next: Setting up libfile-fcntllock-perl (0.22-3build5) ...
    kubearmor-dev-next: Setting up libalgorithm-diff-perl (1.201-1) ...
    kubearmor-dev-next: Setting up libdeflate0:amd64 (1.7-2ubuntu2) ...
    kubearmor-dev-next: Setting up linux-libc-dev:amd64 (5.13.0-20.20) ...
    kubearmor-dev-next: Setting up m4 (1.4.18-5ubuntu1) ...
    kubearmor-dev-next: Setting up libnet1:amd64 (1.1.6+dfsg-3.1build2) ...
    kubearmor-dev-next: Setting up libgomp1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up bzip2 (1.0.8-4ubuntu3) ...
    kubearmor-dev-next: Setting up libffi-dev:amd64 (3.4.2-1ubuntu5) ...
    kubearmor-dev-next: Setting up python3-wheel (0.34.2-1) ...
    kubearmor-dev-next: Setting up libjbig0:amd64 (2.1-3.1build1) ...
    kubearmor-dev-next: Setting up netperf (2.7.0-0.1) ...
    kubearmor-dev-next: Setting up libfakeroot:amd64 (1.25.3-1.1ubuntu2) ...
    kubearmor-dev-next: Setting up libasan6:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up fakeroot (1.25.3-1.1ubuntu2) ...
    kubearmor-dev-next: update-alternatives: using /usr/bin/fakeroot-sysv to provide /usr/bin/fakeroot (fakeroot) in auto mode
    kubearmor-dev-next: Setting up gcc-10-base:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Setting up python3-pygments (2.7.1+dfsg-2.1) ...
    kubearmor-dev-next: Setting up libz3-4:amd64 (4.8.12-1) ...
    kubearmor-dev-next: Setting up libtirpc-dev:amd64 (1.3.2-2) ...
    kubearmor-dev-next: Setting up libpfm4:amd64 (4.11.1+git32-gd0b85fb-1) ...
    kubearmor-dev-next: Setting up rpcsvc-proto (1.4.2-0ubuntu5) ...
    kubearmor-dev-next: Setting up make (4.3-4ubuntu1) ...
    kubearmor-dev-next: Setting up libquadmath0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libmpc3:amd64 (1.2.0-1build1) ...
    kubearmor-dev-next: Setting up libatomic1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up binfmt-support (2.2.1-1) ...
    kubearmor-dev-next: Created symlink /etc/systemd/system/multi-user.target.wants/binfmt-support.service → /lib/systemd/system/binfmt-support.service.
    kubearmor-dev-next: Setting up libwebp6:amd64 (0.6.1-2.1) ...
    kubearmor-dev-next: Setting up fonts-dejavu-core (2.37-2build1) ...
    kubearmor-dev-next: Setting up libfl2:amd64 (2.6.4-8build1) ...
    kubearmor-dev-next: Setting up libjpeg-turbo8:amd64 (2.0.6-0ubuntu2) ...
    kubearmor-dev-next: Setting up libgc1:amd64 (1:8.0.4-3) ...
    kubearmor-dev-next: Setting up libdpkg-perl (1.20.9ubuntu2) ...
    kubearmor-dev-next: Setting up libjsoncpp24:amd64 (1.9.4-4build1) ...
    kubearmor-dev-next: Setting up libubsan1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libsctp1:amd64 (1.0.19+dfsg-1) ...
    kubearmor-dev-next: Setting up libnsl-dev:amd64 (1.3.0-2build1) ...
    kubearmor-dev-next: Setting up librhash0:amd64 (1.4.1-2build1) ...
    kubearmor-dev-next: Setting up libcrypt-dev:amd64 (1:4.4.18-4ubuntu1) ...
    kubearmor-dev-next: Setting up libmd-dev:amd64 (1.0.3-3build1) ...
    kubearmor-dev-next: Setting up bison (2:3.7.6+dfsg-1build1) ...
    kubearmor-dev-next: update-alternatives: using /usr/bin/bison.yacc to provide /usr/bin/yacc (yacc) in auto mode
    kubearmor-dev-next: Setting up libc6-i386 (2.34-0ubuntu3) ...
    kubearmor-dev-next: Setting up python-pip-whl (20.3.4-4) ...
    kubearmor-dev-next: Setting up cmake-data (3.18.4-2ubuntu2) ...
    kubearmor-dev-next: Setting up libjs-jquery (3.5.1+dfsg+~3.5.5-7) ...
    kubearmor-dev-next: Setting up libisl23:amd64 (0.24-1) ...
    kubearmor-dev-next: Setting up libc-dev-bin (2.34-0ubuntu3) ...
    kubearmor-dev-next: Setting up libalgorithm-diff-xs-perl (0.04-6build1) ...
    kubearmor-dev-next: Setting up libbsd-dev:amd64 (0.11.3-1ubuntu2) ...
    kubearmor-dev-next: Setting up libcc1-0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libllvm9:amd64 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up liblsan0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libitm1:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libjs-underscore (1.9.1~dfsg-3) ...
    kubearmor-dev-next: Setting up libalgorithm-merge-perl (0.08-3) ...
    kubearmor-dev-next: Setting up libtsan0:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libjpeg8:amd64 (8c-2ubuntu8) ...
    kubearmor-dev-next: Setting up cpp-11 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libz3-dev:amd64 (4.8.12-1) ...
    kubearmor-dev-next: Setting up flex (2.6.4-8build1) ...
    kubearmor-dev-next: Setting up arping (2.21-2) ...
    kubearmor-dev-next: Setting up llvm-9-tools (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up libclang1-9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up fontconfig-config (2.13.1-4.2ubuntu3) ...
    kubearmor-dev-next: Setting up libclang-cpp9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up libgcc-10-dev:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Setting up libobjc4:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libfl-dev:amd64 (2.6.4-8build1) ...
    kubearmor-dev-next: Setting up dpkg-dev (1.20.9ubuntu2) ...
    kubearmor-dev-next: Setting up lib32gcc-s1 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up lib32stdc++6 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libiperf0:amd64 (3.9-1) ...
    kubearmor-dev-next: Setting up llvm-9-runtime (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up python3-pip (20.3.4-4) ...
    kubearmor-dev-next: Setting up libjs-sphinxdoc (3.5.4-2) ...
    kubearmor-dev-next: Setting up libobjc-10-dev:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Setting up libgcc-11-dev:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up libclang-common-9-dev (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up gcc-11 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up cpp (4:11.2.0-1ubuntu1) ...
    kubearmor-dev-next: Setting up cmake (3.18.4-2ubuntu2) ...
    kubearmor-dev-next: Setting up libc6-dev:amd64 (2.34-0ubuntu3) ...
    kubearmor-dev-next: Setting up libtiff5:amd64 (4.3.0-1) ...
    kubearmor-dev-next: Setting up libfontconfig1:amd64 (2.13.1-4.2ubuntu3) ...
    kubearmor-dev-next: Setting up libncurses-dev:amd64 (6.2+20201114-2build1) ...
    kubearmor-dev-next: Setting up libstdc++-10-dev:amd64 (10.3.0-11ubuntu1) ...
    kubearmor-dev-next: Setting up clang-9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up iperf3 (3.9-1) ...
    kubearmor-dev-next: Setting up gcc (4:11.2.0-1ubuntu1) ...
    kubearmor-dev-next: Setting up libexpat1-dev:amd64 (2.4.1-2) ...
    kubearmor-dev-next: Setting up llvm-9 (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up libclang-9-dev (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up libedit-dev:amd64 (3.1-20191231-2build1) ...
    kubearmor-dev-next: Setting up libgd3:amd64 (2.3.0-2ubuntu1) ...
    kubearmor-dev-next: Setting up libstdc++-11-dev:amd64 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up zlib1g-dev:amd64 (1:1.2.11.dfsg-2ubuntu7) ...
    kubearmor-dev-next: Setting up libc-devtools (2.34-0ubuntu3) ...
    kubearmor-dev-next: Setting up g++-11 (11.2.0-7ubuntu2) ...
    kubearmor-dev-next: Setting up llvm-9-dev (1:9.0.1-16.1ubuntu1) ...
    kubearmor-dev-next: Setting up libpython3.9-dev:amd64 (3.9.7-2build1) ...
    kubearmor-dev-next: Setting up libelf-dev:amd64 (0.185-1build1) ...
    kubearmor-dev-next: Setting up g++ (4:11.2.0-1ubuntu1) ...
    kubearmor-dev-next: update-alternatives: using /usr/bin/g++ to provide /usr/bin/c++ (c++) in auto mode
    kubearmor-dev-next: Setting up python3.9-dev (3.9.7-2build1) ...
    kubearmor-dev-next: Setting up build-essential (12.9ubuntu2) ...
    kubearmor-dev-next: Setting up libpython3-dev:amd64 (3.9.4-1build1) ...
    kubearmor-dev-next: Setting up python3-dev (3.9.4-1build1) ...
    kubearmor-dev-next: Processing triggers for libc-bin (2.34-0ubuntu3) ...
    kubearmor-dev-next: Processing triggers for man-db (2.9.4-2) ...
    kubearmor-dev-next: Processing triggers for install-info (6.7.0.dfsg.2-6) ...
    kubearmor-dev-next: 
    kubearmor-dev-next: Running kernel seems to be up-to-date.
    kubearmor-dev-next: 
    kubearmor-dev-next: No services need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No containers need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No user sessions are running outdated binaries.
    kubearmor-dev-next: -- The C compiler identification is GNU 11.2.0
    kubearmor-dev-next: -- The CXX compiler identification is GNU 11.2.0
    kubearmor-dev-next: -- Detecting C compiler ABI info
    kubearmor-dev-next: -- Detecting C compiler ABI info - done
    kubearmor-dev-next: -- Check for working C compiler: /usr/bin/cc - skipped
    kubearmor-dev-next: -- Detecting C compile features
    kubearmor-dev-next: -- Detecting C compile features - done
    kubearmor-dev-next: -- Detecting CXX compiler ABI info
    kubearmor-dev-next: -- Detecting CXX compiler ABI info - done
    kubearmor-dev-next: -- Check for working CXX compiler: /usr/bin/c++ - skipped
    kubearmor-dev-next: -- Detecting CXX compile features
    kubearmor-dev-next: -- Detecting CXX compile features - done
    kubearmor-dev-next: Submodule 'src/cc/libbpf' (https://github.com/libbpf/libbpf.git) registered for path 'src/cc/libbpf'
    kubearmor-dev-next: Cloning into '/tmp/build/bcc/src/cc/libbpf'...
    kubearmor-dev-next: Submodule path 'src/cc/libbpf': checked out '5579664205e42194e1921d69d0839f660c801a4d'
    kubearmor-dev-next: -- Latest recognized Git tag is v0.22.0
    kubearmor-dev-next: -- Git HEAD is bced75aae53c22524fd335b04a005ce60384b8a8
    kubearmor-dev-next: -- Revision is 0.22.0-bced75aa
    kubearmor-dev-next: -- Performing Test HAVE_NO_PIE_FLAG
    kubearmor-dev-next: -- Performing Test HAVE_NO_PIE_FLAG - Success
    kubearmor-dev-next: -- Performing Test HAVE_REALLOCARRAY_SUPPORT
    kubearmor-dev-next: -- Performing Test HAVE_REALLOCARRAY_SUPPORT - Success
    kubearmor-dev-next: -- Found LLVM: /usr/lib/llvm-9/include 9.0.1
    kubearmor-dev-next: -- Found BISON: /usr/bin/bison (found version "3.7.6")
    kubearmor-dev-next: -- Found FLEX: /usr/bin/flex (found version "2.6.4")
    kubearmor-dev-next: -- Found LibElf: /usr/lib/x86_64-linux-gnu/libelf.so
    kubearmor-dev-next: -- Performing Test ELF_GETSHDRSTRNDX
    kubearmor-dev-next: -- Performing Test ELF_GETSHDRSTRNDX - Success
    kubearmor-dev-next: -- Could NOT find LibDebuginfod (missing: LIBDEBUGINFOD_LIBRARIES LIBDEBUGINFOD_INCLUDE_DIRS)
    kubearmor-dev-next: -- Using static-libstdc++
    kubearmor-dev-next: -- Could NOT find LuaJIT (missing: LUAJIT_LIBRARIES LUAJIT_INCLUDE_DIR)
    kubearmor-dev-next: -- Configuring done
    kubearmor-dev-next: -- Generating done
    kubearmor-dev-next: -- Build files have been written to: /tmp/build/bcc/build
    kubearmor-dev-next: Scanning dependencies of target bcc-loader-static
    kubearmor-dev-next: Scanning dependencies of target api-static
    kubearmor-dev-next: [  0%] Building CXX object src/cc/CMakeFiles/bcc-loader-static.dir/bcc_syms.cc.o
    kubearmor-dev-next: [  0%] Building CXX object src/cc/api/CMakeFiles/api-static.dir/BPF.cc.o
    kubearmor-dev-next: Scanning dependencies of target bpf-static
    kubearmor-dev-next: [  0%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf.c.o
    kubearmor-dev-next: Scanning dependencies of target clang_frontend
    kubearmor-dev-next: [  0%] Building CXX object src/cc/frontends/clang/CMakeFiles/clang_frontend.dir/loader.cc.o
    kubearmor-dev-next: [  0%] Building C object src/cc/CMakeFiles/bpf-static.dir/perf_reader.c.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/loader.cc:57:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/DeclOpenMP.h:97:1: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    97 | /// #pragma omp declare reduction (foo : int,float : omp_out += omp_in) \
    kubearmor-dev-next:       | ^
    kubearmor-dev-next: [  1%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/bpf.c.o
    kubearmor-dev-next: [  1%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/bpf_prog_linfo.c.o
    kubearmor-dev-next: [  1%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/btf.c.o
    kubearmor-dev-next: [  2%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/btf_dump.c.o
    kubearmor-dev-next: [  2%] Building C object src/cc/CMakeFiles/bcc-loader-static.dir/bcc_elf.c.o
    kubearmor-dev-next: [  2%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/gen_loader.c.o
    kubearmor-dev-next: [  3%] Building C object src/cc/CMakeFiles/bcc-loader-static.dir/bcc_perf_map.c.o
    kubearmor-dev-next: [  3%] Building C object src/cc/CMakeFiles/bcc-loader-static.dir/bcc_proc.c.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/TypeLoc.h:17,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTTypeTraits.h:24,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTContext.h:18,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/Frontend/ASTUnit.h:17,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/Frontend/FrontendAction.h:23,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/CodeGen/CodeGenAction.h:12,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/loader.cc:38:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h: In static member function ‘static clang::ParamIdx clang::ParamIdx::deserialize(clang::ParamIdx::SerialType)’:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next:   262 |     ParamIdx P(*reinterpret_cast<ParamIdx *>(&S));
    kubearmor-dev-next:       |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next: [  3%] Building CXX object src/cc/CMakeFiles/bcc-loader-static.dir/common.cc.o
    kubearmor-dev-next: [  3%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/hashmap.c.o
    kubearmor-dev-next: [  4%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/libbpf.c.o
    kubearmor-dev-next: [  5%] Building CXX object src/cc/api/CMakeFiles/api-static.dir/BPFTable.cc.o
    kubearmor-dev-next: [  6%] Linking CXX static library libbcc-loader-static.a
    kubearmor-dev-next: [  6%] Built target bcc-loader-static
    kubearmor-dev-next: Scanning dependencies of target usdt-static
    kubearmor-dev-next: [  6%] Building CXX object src/cc/usdt/CMakeFiles/usdt-static.dir/usdt_args.cc.o
    kubearmor-dev-next: [  6%] Linking CXX static library libapi-static.a
    kubearmor-dev-next: [  6%] Built target api-static
    kubearmor-dev-next: [  7%] Building CXX object src/cc/usdt/CMakeFiles/usdt-static.dir/usdt.cc.o
    kubearmor-dev-next: [  7%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/libbpf_errno.c.o
    kubearmor-dev-next: [  7%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/libbpf_probes.c.o
    kubearmor-dev-next: [  8%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/linker.c.o
    kubearmor-dev-next: [  8%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/netlink.c.o
    kubearmor-dev-next: [  8%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/nlattr.c.o
    kubearmor-dev-next: [  9%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/relo_core.c.o
    kubearmor-dev-next: [  9%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/ringbuf.c.o
    kubearmor-dev-next: [  9%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/str_error.c.o
    kubearmor-dev-next: [ 10%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/strset.c.o
    kubearmor-dev-next: [ 10%] Building C object src/cc/CMakeFiles/bpf-static.dir/libbpf/src/xsk.c.o
    kubearmor-dev-next: [ 10%] Building CXX object src/cc/CMakeFiles/bpf-static.dir/bcc_syms.cc.o
    kubearmor-dev-next: [ 11%] Building C object src/cc/CMakeFiles/bpf-static.dir/bcc_elf.c.o
    kubearmor-dev-next: [ 11%] Building C object src/cc/CMakeFiles/bpf-static.dir/bcc_perf_map.c.o
    kubearmor-dev-next: [ 11%] Building C object src/cc/CMakeFiles/bpf-static.dir/bcc_proc.c.o
    kubearmor-dev-next: [ 12%] Building CXX object src/cc/CMakeFiles/bpf-static.dir/common.cc.o
    kubearmor-dev-next: [ 12%] Building CXX object src/cc/CMakeFiles/bpf-static.dir/usdt/usdt.cc.o
    kubearmor-dev-next: [ 12%] Linking CXX static library libusdt-static.a
    kubearmor-dev-next: [ 12%] Built target usdt-static
    kubearmor-dev-next: [ 13%] [FLEX][Lexer] Building scanner with flex 2.6.4
    kubearmor-dev-next: lexer.ll:110: warning, -s option given but default rule can be matched
    kubearmor-dev-next: [ 13%] [BISON][Parser] Building parser with bison 3.7.6
    kubearmor-dev-next: parser.yy:19.1-28: warning: deprecated directive: ‘%define namespace "ebpf::cc"’, use ‘%define api.namespace {ebpf::cc}’ [-Wdeprecated]
    kubearmor-dev-next:    19 | %define namespace "ebpf::cc"
    kubearmor-dev-next:       | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next:       | %define api.namespace {ebpf::cc}
    kubearmor-dev-next: parser.yy:20.1-39: warning: deprecated directive: ‘%define parser_class_name "BisonParser"’, use ‘%define api.parser.class {BisonParser}’ [-Wdeprecated]
    kubearmor-dev-next:    20 | %define parser_class_name "BisonParser"
    kubearmor-dev-next:       | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next:       | %define api.parser.class {BisonParser}
    kubearmor-dev-next: parser.yy:19.1-28: warning: %define variable 'api.namespace' requires '{...}' values [-Wdeprecated]
    kubearmor-dev-next:    19 | %define namespace "ebpf::cc"
    kubearmor-dev-next:       | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: parser.yy:20.1-39: warning: %define variable 'api.parser.class' requires '{...}' values [-Wdeprecated]
    kubearmor-dev-next:    20 | %define parser_class_name "BisonParser"
    kubearmor-dev-next:       | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: parser.yy: warning: fix-its can be applied.  Rerun with option '--update'. [-Wother]
    kubearmor-dev-next: Scanning dependencies of target b_frontend
    kubearmor-dev-next: [ 13%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/loader.cc.o
    kubearmor-dev-next: [ 14%] Building CXX object src/cc/frontends/clang/CMakeFiles/clang_frontend.dir/b_frontend_action.cc.o
    kubearmor-dev-next: [ 14%] Building CXX object src/cc/frontends/clang/CMakeFiles/clang_frontend.dir/tp_frontend_action.cc.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.cc:31:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/DeclOpenMP.h:97:1: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    97 | /// #pragma omp declare reduction (foo : int,float : omp_out += omp_in) \
    kubearmor-dev-next:       | ^
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/tp_frontend_action.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/tp_frontend_action.cc:32:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/DeclOpenMP.h:97:1: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    97 | /// #pragma omp declare reduction (foo : int,float : omp_out += omp_in) \
    kubearmor-dev-next:       | ^
    kubearmor-dev-next: [ 14%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/codegen_llvm.cc.o
    kubearmor-dev-next: [ 14%] Building CXX object src/cc/CMakeFiles/bpf-static.dir/usdt/usdt_args.cc.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/TypeLoc.h:17,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTTypeTraits.h:24,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTContext.h:18,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.cc:23:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h: In static member function ‘static clang::ParamIdx clang::ParamIdx::deserialize(clang::ParamIdx::SerialType)’:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next:   262 |     ParamIdx P(*reinterpret_cast<ParamIdx *>(&S));
    kubearmor-dev-next:       |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/TypeLoc.h:17,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTTypeTraits.h:24,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTContext.h:18,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/tp_frontend_action.cc:25:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h: In static member function ‘static clang::ParamIdx clang::ParamIdx::deserialize(clang::ParamIdx::SerialType)’:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next:   262 |     ParamIdx P(*reinterpret_cast<ParamIdx *>(&S));
    kubearmor-dev-next:       |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next: [ 15%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/node.cc.o
    kubearmor-dev-next: [ 15%] Linking CXX static library libbcc_bpf.a
    kubearmor-dev-next: [ 15%] Built target bpf-static
    kubearmor-dev-next: [ 15%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/parser.cc.o
    kubearmor-dev-next: Scanning dependencies of target bpf-shared
    kubearmor-dev-next: [ 15%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf.c.o
    kubearmor-dev-next: [ 16%] Building C object src/cc/CMakeFiles/bpf-shared.dir/perf_reader.c.o
    kubearmor-dev-next: [ 16%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/bpf.c.o
    kubearmor-dev-next: [ 16%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/bpf_prog_linfo.c.o
    kubearmor-dev-next: [ 17%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/btf.c.o
    kubearmor-dev-next: [ 17%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/btf_dump.c.o
    kubearmor-dev-next: [ 17%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/printer.cc.o
    kubearmor-dev-next: [ 17%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/gen_loader.c.o
    kubearmor-dev-next: [ 18%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/hashmap.c.o
    kubearmor-dev-next: [ 18%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/libbpf.c.o
    kubearmor-dev-next: [ 19%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/type_check.cc.o
    kubearmor-dev-next: [ 19%] Building CXX object src/cc/frontends/clang/CMakeFiles/clang_frontend.dir/kbuild_helper.cc.o
    kubearmor-dev-next: /tmp/build/bcc/src/cc/frontends/clang/kbuild_helper.cc:80:3: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    80 |   // USERINCLUDE    := \
    kubearmor-dev-next:       |   ^
    kubearmor-dev-next: /tmp/build/bcc/src/cc/frontends/clang/kbuild_helper.cc:89:3: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    89 |   // LINUXINCLUDE    := \
    kubearmor-dev-next:       |   ^
    kubearmor-dev-next: [ 20%] Building CXX object src/cc/frontends/clang/CMakeFiles/clang_frontend.dir/__/__/common.cc.o
    kubearmor-dev-next: [ 20%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/parser.yy.cc.o
    kubearmor-dev-next: [ 20%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/libbpf_errno.c.o
    kubearmor-dev-next: [ 21%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/libbpf_probes.c.o
    kubearmor-dev-next: [ 21%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/linker.c.o
    kubearmor-dev-next: [ 21%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/netlink.c.o
    kubearmor-dev-next: [ 22%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/nlattr.c.o
    kubearmor-dev-next: [ 22%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/relo_core.c.o
    kubearmor-dev-next: [ 22%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/ringbuf.c.o
    kubearmor-dev-next: [ 23%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/str_error.c.o
    kubearmor-dev-next: [ 23%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/strset.c.o
    kubearmor-dev-next: [ 23%] Building C object src/cc/CMakeFiles/bpf-shared.dir/libbpf/src/xsk.c.o
    kubearmor-dev-next: [ 24%] Building CXX object src/cc/CMakeFiles/bpf-shared.dir/bcc_syms.cc.o
    kubearmor-dev-next: [ 24%] Building C object src/cc/CMakeFiles/bpf-shared.dir/bcc_elf.c.o
    kubearmor-dev-next: [ 24%] Building C object src/cc/CMakeFiles/bpf-shared.dir/bcc_perf_map.c.o
    kubearmor-dev-next: [ 25%] Building C object src/cc/CMakeFiles/bpf-shared.dir/bcc_proc.c.o
    kubearmor-dev-next: [ 25%] Building CXX object src/cc/CMakeFiles/bpf-shared.dir/common.cc.o
    kubearmor-dev-next: [ 25%] Building CXX object src/cc/frontends/b/CMakeFiles/b_frontend.dir/lexer.ll.cc.o
    kubearmor-dev-next: [ 25%] Building CXX object src/cc/CMakeFiles/bpf-shared.dir/usdt/usdt.cc.o
    kubearmor-dev-next: [ 25%] Building CXX object src/cc/CMakeFiles/bpf-shared.dir/usdt/usdt_args.cc.o
    kubearmor-dev-next: [ 26%] Linking CXX static library libb_frontend.a
    kubearmor-dev-next: [ 26%] Built target b_frontend
    kubearmor-dev-next: Scanning dependencies of target bcc_py_python3
    kubearmor-dev-next: [ 26%] Building sdist for python3
    kubearmor-dev-next: running sdist
    kubearmor-dev-next: running check
    kubearmor-dev-next: warning: sdist: manifest template 'MANIFEST.in' does not exist (using default file list)
    kubearmor-dev-next: 
    kubearmor-dev-next: warning: sdist: standard file not found: should have one of README, README.txt, README.rst
    kubearmor-dev-next: 
    kubearmor-dev-next: writing manifest file 'MANIFEST'
    kubearmor-dev-next: creating bcc-0.22.0-bced75aa
    kubearmor-dev-next: creating bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: making hard links in bcc-0.22.0-bced75aa...
    kubearmor-dev-next: hard linking setup.py -> bcc-0.22.0-bced75aa
    kubearmor-dev-next: hard linking bcc/__init__.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/containers.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/disassembler.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/libbcc.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/perf.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/syscall.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/table.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/tcp.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/usdt.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/utils.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: hard linking bcc/version.py -> bcc-0.22.0-bced75aa/bcc
    kubearmor-dev-next: creating dist
    kubearmor-dev-next: Creating tar archive
    kubearmor-dev-next: removing 'bcc-0.22.0-bced75aa' (and everything under it)
    kubearmor-dev-next: [ 26%] Built target bcc_py_python3
    kubearmor-dev-next: Scanning dependencies of target bps
    kubearmor-dev-next: [ 27%] Building C object introspection/CMakeFiles/bps.dir/bps.c.o
    kubearmor-dev-next: [ 27%] Linking CXX executable bps
    kubearmor-dev-next: [ 27%] Built target bps
    kubearmor-dev-next: Scanning dependencies of target man
    kubearmor-dev-next: [ 27%] Generating argdist.8.gz
    kubearmor-dev-next: [ 28%] Generating bashreadline.8.gz
    kubearmor-dev-next: [ 28%] Generating bindsnoop.8.gz
    kubearmor-dev-next: [ 28%] Generating biolatency.8.gz
    kubearmor-dev-next: [ 29%] Generating biolatpcts.8.gz
    kubearmor-dev-next: [ 29%] Generating biosnoop.8.gz
    kubearmor-dev-next: [ 29%] Generating biotop.8.gz
    kubearmor-dev-next: [ 30%] Generating bitesize.8.gz
    kubearmor-dev-next: [ 30%] Generating bpflist.8.gz
    kubearmor-dev-next: [ 30%] Generating bps.8.gz
    kubearmor-dev-next: [ 31%] Generating btrfsdist.8.gz
    kubearmor-dev-next: [ 31%] Generating btrfsslower.8.gz
    kubearmor-dev-next: [ 31%] Generating cachestat.8.gz
    kubearmor-dev-next: [ 32%] Generating cachetop.8.gz
    kubearmor-dev-next: [ 32%] Generating capable.8.gz
    kubearmor-dev-next: [ 32%] Generating cobjnew.8.gz
    kubearmor-dev-next: [ 33%] Generating compactsnoop.8.gz
    kubearmor-dev-next: [ 33%] Generating cpudist.8.gz
    kubearmor-dev-next: [ 33%] Generating cpuunclaimed.8.gz
    kubearmor-dev-next: [ 33%] Generating criticalstat.8.gz
    kubearmor-dev-next: [ 34%] Generating cthreads.8.gz
    kubearmor-dev-next: [ 34%] Generating dbslower.8.gz
    kubearmor-dev-next: [ 34%] Generating dbstat.8.gz
    kubearmor-dev-next: [ 35%] Generating dcsnoop.8.gz
    kubearmor-dev-next: [ 35%] Generating dcstat.8.gz
    kubearmor-dev-next: [ 35%] Generating deadlock.8.gz
    kubearmor-dev-next: [ 36%] Generating dirtop.8.gz
    kubearmor-dev-next: [ 36%] Generating drsnoop.8.gz
    kubearmor-dev-next: [ 36%] Generating execsnoop.8.gz
    kubearmor-dev-next: [ 37%] Generating exitsnoop.8.gz
    kubearmor-dev-next: [ 37%] Generating ext4dist.8.gz
    kubearmor-dev-next: [ 37%] Generating ext4slower.8.gz
    kubearmor-dev-next: [ 38%] Generating filelife.8.gz
    kubearmor-dev-next: [ 38%] Generating fileslower.8.gz
    kubearmor-dev-next: [ 38%] Generating filetop.8.gz
    kubearmor-dev-next: [ 39%] Generating funccount.8.gz
    kubearmor-dev-next: [ 39%] Generating funcinterval.8.gz
    kubearmor-dev-next: [ 39%] Generating funclatency.8.gz
    kubearmor-dev-next: [ 40%] Generating funcslower.8.gz
    kubearmor-dev-next: [ 40%] Generating gethostlatency.8.gz
    kubearmor-dev-next: [ 40%] Generating hardirqs.8.gz
    kubearmor-dev-next: [ 41%] Generating inject.8.gz
    kubearmor-dev-next: [ 41%] Generating javacalls.8.gz
    kubearmor-dev-next: [ 41%] Generating javaflow.8.gz
    kubearmor-dev-next: [ 42%] Generating javagc.8.gz
    kubearmor-dev-next: [ 42%] Generating javaobjnew.8.gz
    kubearmor-dev-next: [ 42%] Generating javastat.8.gz
    kubearmor-dev-next: [ 42%] Generating javathreads.8.gz
    kubearmor-dev-next: [ 43%] Generating killsnoop.8.gz
    kubearmor-dev-next: [ 43%] Generating klockstat.8.gz
    kubearmor-dev-next: [ 43%] Generating ksnoop.8.gz
    kubearmor-dev-next: [ 44%] Generating kvmexit.8.gz
    kubearmor-dev-next: [ 44%] Generating llcstat.8.gz
    kubearmor-dev-next: [ 44%] Generating mdflush.8.gz
    kubearmor-dev-next: [ 45%] Generating memleak.8.gz
    kubearmor-dev-next: [ 45%] Generating mountsnoop.8.gz
    kubearmor-dev-next: [ 45%] Generating mysqld_qslower.8.gz
    kubearmor-dev-next: [ 46%] Generating netqtop.8.gz
    kubearmor-dev-next: [ 46%] Generating nfsdist.8.gz
    kubearmor-dev-next: [ 46%] Generating nfsslower.8.gz
    kubearmor-dev-next: [ 47%] Generating nodegc.8.gz
    kubearmor-dev-next: [ 47%] Generating nodestat.8.gz
    kubearmor-dev-next: [ 47%] Generating offcputime.8.gz
    kubearmor-dev-next: [ 48%] Generating offwaketime.8.gz
    kubearmor-dev-next: [ 48%] Generating oomkill.8.gz
    kubearmor-dev-next: [ 48%] Generating opensnoop.8.gz
    kubearmor-dev-next: [ 49%] Generating perlcalls.8.gz
    kubearmor-dev-next: [ 49%] Generating perlflow.8.gz
    kubearmor-dev-next: [ 49%] Generating perlstat.8.gz
    kubearmor-dev-next: [ 50%] Generating phpcalls.8.gz
    kubearmor-dev-next: [ 50%] Generating phpflow.8.gz
    kubearmor-dev-next: [ 50%] Generating phpstat.8.gz
    kubearmor-dev-next: [ 51%] Generating pidpersec.8.gz
    kubearmor-dev-next: [ 51%] Generating profile.8.gz
    kubearmor-dev-next: [ 51%] Generating pythoncalls.8.gz
    kubearmor-dev-next: [ 51%] Generating pythonflow.8.gz
    kubearmor-dev-next: [ 52%] Generating pythongc.8.gz
    kubearmor-dev-next: [ 52%] Generating pythonstat.8.gz
    kubearmor-dev-next: [ 52%] Generating readahead.8.gz
    kubearmor-dev-next: [ 53%] Generating reset-trace.8.gz
    kubearmor-dev-next: [ 53%] Generating rubycalls.8.gz
    kubearmor-dev-next: [ 53%] Generating rubyflow.8.gz
    kubearmor-dev-next: [ 54%] Generating rubygc.8.gz
    kubearmor-dev-next: [ 54%] Generating rubyobjnew.8.gz
    kubearmor-dev-next: [ 54%] Generating rubystat.8.gz
    kubearmor-dev-next: [ 55%] Generating runqlat.8.gz
    kubearmor-dev-next: [ 55%] Generating runqlen.8.gz
    kubearmor-dev-next: [ 55%] Generating runqslower.8.gz
    kubearmor-dev-next: [ 56%] Generating shmsnoop.8.gz
    kubearmor-dev-next: [ 56%] Generating slabratetop.8.gz
    kubearmor-dev-next: [ 56%] Generating sofdsnoop.8.gz
    kubearmor-dev-next: [ 57%] Generating softirqs.8.gz
    kubearmor-dev-next: [ 57%] Generating solisten.8.gz
    kubearmor-dev-next: [ 57%] Generating spfdsnoop.8.gz
    kubearmor-dev-next: [ 58%] Generating sslsniff.8.gz
    kubearmor-dev-next: [ 58%] Generating stackcount.8.gz
    kubearmor-dev-next: [ 58%] Generating statsnoop.8.gz
    kubearmor-dev-next: [ 59%] Generating swapin.8.gz
    kubearmor-dev-next: [ 59%] Generating syncsnoop.8.gz
    kubearmor-dev-next: [ 59%] Generating syscount.8.gz
    kubearmor-dev-next: [ 60%] Generating tclcalls.8.gz
    kubearmor-dev-next: [ 60%] Generating tclflow.8.gz
    kubearmor-dev-next: [ 60%] Generating tclobjnew.8.gz
    kubearmor-dev-next: [ 60%] Generating tclstat.8.gz
    kubearmor-dev-next: [ 61%] Generating tcpaccept.8.gz
    kubearmor-dev-next: [ 61%] Generating tcpconnect.8.gz
    kubearmor-dev-next: [ 61%] Generating tcpconnlat.8.gz
    kubearmor-dev-next: [ 62%] Generating tcpdrop.8.gz
    kubearmor-dev-next: [ 62%] Generating tcplife.8.gz
    kubearmor-dev-next: [ 62%] Generating tcpretrans.8.gz
    kubearmor-dev-next: [ 63%] Generating tcprtt.8.gz
    kubearmor-dev-next: [ 63%] Generating tcpstates.8.gz
    kubearmor-dev-next: [ 63%] Generating tcpsubnet.8.gz
    kubearmor-dev-next: [ 64%] Generating tcpsynbl.8.gz
    kubearmor-dev-next: [ 64%] Generating tcptop.8.gz
    kubearmor-dev-next: [ 64%] Generating tcptracer.8.gz
    kubearmor-dev-next: [ 65%] Generating threadsnoop.8.gz
    kubearmor-dev-next: [ 65%] Generating tplist.8.gz
    kubearmor-dev-next: [ 65%] Generating trace.8.gz
    kubearmor-dev-next: [ 66%] Generating ttysnoop.8.gz
    kubearmor-dev-next: [ 66%] Generating ucalls.8.gz
    kubearmor-dev-next: [ 66%] Generating uflow.8.gz
    kubearmor-dev-next: [ 67%] Generating ugc.8.gz
    kubearmor-dev-next: Scanning dependencies of target usdt_test_lib
    kubearmor-dev-next: [ 67%] Generating uobjnew.8.gz
    kubearmor-dev-next: [ 67%] Building CXX object tests/cc/CMakeFiles/usdt_test_lib.dir/usdt_test_lib.cc.o
    kubearmor-dev-next: [ 67%] Generating ustat.8.gz
    kubearmor-dev-next: [ 68%] Generating uthreads.8.gz
    kubearmor-dev-next: [ 68%] Generating vfscount.8.gz
    kubearmor-dev-next: [ 68%] Generating vfsstat.8.gz
    kubearmor-dev-next: [ 69%] Generating virtiostat.8.gz
    kubearmor-dev-next: [ 70%] Linking CXX shared library libusdt_test_lib.so
    kubearmor-dev-next: [ 70%] Generating wakeuptime.8.gz
    kubearmor-dev-next: [ 70%] Generating xfsdist.8.gz
    kubearmor-dev-next: [ 70%] Generating xfsslower.8.gz
    kubearmor-dev-next: [ 70%] Built target usdt_test_lib
    kubearmor-dev-next: [ 71%] Generating zfsdist.8.gz
    kubearmor-dev-next: [ 71%] Generating zfsslower.8.gz
    kubearmor-dev-next: [ 71%] Built target man
    kubearmor-dev-next: [ 72%] Linking CXX shared library libbcc_bpf.so
    kubearmor-dev-next: [ 72%] Built target bpf-shared
    kubearmor-dev-next: [ 72%] Linking CXX static library libclang_frontend.a
    kubearmor-dev-next: [ 72%] Built target clang_frontend
    kubearmor-dev-next: Scanning dependencies of target bcc-shared
    kubearmor-dev-next: Scanning dependencies of target bcc-static
    kubearmor-dev-next: [ 72%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/bcc_common.cc.o
    kubearmor-dev-next: [ 72%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/link_all.cc.o
    kubearmor-dev-next: [ 72%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/bcc_common.cc.o
    kubearmor-dev-next: [ 73%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/bpf_module.cc.o
    kubearmor-dev-next: [ 73%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/bcc_btf.cc.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module.cc:43:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/DeclOpenMP.h:97:1: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    97 | /// #pragma omp declare reduction (foo : int,float : omp_out += omp_in) \
    kubearmor-dev-next:       | ^
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bcc_btf.cc: In member function ‘int ebpf::BTF::get_btf_info(const char*, void**, unsigned int*, unsigned int*, void**, unsigned int*, unsigned int*)’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bcc_btf.cc:315:33: warning: ‘int btf_ext__reloc_func_info(const btf*, const btf_ext*, const char*, __u32, void**, __u32*)’ is deprecated: btf_ext__reloc_func_info was never meant as a public API and has wrong assumptions embedded in it; it will be removed in the future libbpf versions [-Wdeprecated-declarations]
    kubearmor-dev-next:   315 |   ret = btf_ext__reloc_func_info(btf_, btf_ext_, fname, 0,
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next:   316 |         func_info, func_info_cnt);
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: In file included from /tmp/build/bcc/src/cc/bcc_libbpf_inc.h:9,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bcc_btf.cc:22:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/libbpf/src/btf.h:88:5: note: declared here
    kubearmor-dev-next:    88 | int btf_ext__reloc_func_info(const struct btf *btf,
    kubearmor-dev-next:       |     ^~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bcc_btf.cc:322:33: warning: ‘int btf_ext__reloc_line_info(const btf*, const btf_ext*, const char*, __u32, void**, __u32*)’ is deprecated: btf_ext__reloc_line_info was never meant as a public API and has wrong assumptions embedded in it; it will be removed in the future libbpf versions [-Wdeprecated-declarations]
    kubearmor-dev-next:   322 |   ret = btf_ext__reloc_line_info(btf_, btf_ext_, fname, 0,
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next:   323 |         line_info, line_info_cnt);
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: In file included from /tmp/build/bcc/src/cc/bcc_libbpf_inc.h:9,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bcc_btf.cc:22:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/libbpf/src/btf.h:93:5: note: declared here
    kubearmor-dev-next:    93 | int btf_ext__reloc_line_info(const struct btf *btf,
    kubearmor-dev-next:       |     ^~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: [ 73%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/exported_files.cc.o
    kubearmor-dev-next: [ 74%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/bpf_module.cc.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module.cc:43:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/DeclOpenMP.h:97:1: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    97 | /// #pragma omp declare reduction (foo : int,float : omp_out += omp_in) \
    kubearmor-dev-next:       | ^
    kubearmor-dev-next: [ 74%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/bcc_debug.cc.o
    kubearmor-dev-next: [ 75%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/bpf_module_rw_engine.cc.o
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc: In member function ‘std::unique_ptr<llvm::ExecutionEngine> ebpf::BPFModule::finalize_rw(std::unique_ptr<llvm::Module>)’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:360:36: warning: ‘void llvm::EngineBuilder::setUseOrcMCJITReplacement(bool)’ is deprecated [-Wdeprecated-declarations]
    kubearmor-dev-next:   360 |   builder.setUseOrcMCJITReplacement(false);
    kubearmor-dev-next:       |   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/llvm/ExecutionEngine/MCJIT.h:17,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:20:
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ExecutionEngine/ExecutionEngine.h:668:6: note: declared here
    kubearmor-dev-next:   668 | void EngineBuilder::setUseOrcMCJITReplacement(bool UseOrcMCJITReplacement) {
    kubearmor-dev-next:       |      ^~~~~~~~~~~~~
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/llvm/ExecutionEngine/ExecutionEngine.h:18,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/llvm/ExecutionEngine/MCJIT.h:17,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:20:
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h: In instantiation of ‘llvm::ArrayRef<T>::ArrayRef(const std::initializer_list<_Tp>&) [with T = llvm::Value*]’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:79:35:   required from here
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h:101:37: warning: initializing ‘llvm::ArrayRef<llvm::Value*>::Data’ from ‘std::initializer_list<llvm::Value*>::begin’ does not extend the lifetime of the underlying array [-Winit-list-lifetime]
    kubearmor-dev-next:   101 |     : Data(Vec.begin() == Vec.end() ? (T*)nullptr : Vec.begin()),
    kubearmor-dev-next:       |            ~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h: In instantiation of ‘llvm::ArrayRef<T>::ArrayRef(const std::initializer_list<_Tp>&) [with T = llvm::Type*]’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:231:51:   required from here
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h:101:37: warning: initializing ‘llvm::ArrayRef<llvm::Type*>::Data’ from ‘std::initializer_list<llvm::Type*>::begin’ does not extend the lifetime of the underlying array [-Winit-list-lifetime]
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:16,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module.cc:43:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h: In static member function ‘static clang::ParamIdx clang::ParamIdx::deserialize(clang::ParamIdx::SerialType)’:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next:   262 |     ParamIdx P(*reinterpret_cast<ParamIdx *>(&S));
    kubearmor-dev-next:       |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:16,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/frontends/clang/b_frontend_action.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module.cc:43:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h: In static member function ‘static clang::ParamIdx clang::ParamIdx::deserialize(clang::ParamIdx::SerialType)’:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next:   262 |     ParamIdx P(*reinterpret_cast<ParamIdx *>(&S));
    kubearmor-dev-next:       |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next: [ 75%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/table_storage.cc.o
    kubearmor-dev-next: [ 75%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/shared_table.cc.o
    kubearmor-dev-next: [ 76%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/bpffs_table.cc.o
    kubearmor-dev-next: [ 76%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/json_map_decl_visitor.cc.o
    kubearmor-dev-next: [ 76%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/bcc_syms.cc.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/json_map_decl_visitor.cc:22:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/DeclOpenMP.h:97:1: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    97 | /// #pragma omp declare reduction (foo : int,float : omp_out += omp_in) \
    kubearmor-dev-next:       | ^
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module.cc: In member function ‘int ebpf::BPFModule::finalize()’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module.cc:481:36: warning: ‘void llvm::EngineBuilder::setUseOrcMCJITReplacement(bool)’ is deprecated [-Wdeprecated-declarations]
    kubearmor-dev-next:   481 |   builder.setUseOrcMCJITReplacement(false);
    kubearmor-dev-next:       |   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/llvm/ExecutionEngine/MCJIT.h:17,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module.cc:26:
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ExecutionEngine/ExecutionEngine.h:668:6: note: declared here
    kubearmor-dev-next:   668 | void EngineBuilder::setUseOrcMCJITReplacement(bool UseOrcMCJITReplacement) {
    kubearmor-dev-next:       |      ^~~~~~~~~~~~~
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module.cc: In member function ‘int ebpf::BPFModule::finalize()’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module.cc:481:36: warning: ‘void llvm::EngineBuilder::setUseOrcMCJITReplacement(bool)’ is deprecated [-Wdeprecated-declarations]
    kubearmor-dev-next:   481 |   builder.setUseOrcMCJITReplacement(false);
    kubearmor-dev-next:       |   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/llvm/ExecutionEngine/MCJIT.h:17,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module.cc:26:
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ExecutionEngine/ExecutionEngine.h:668:6: note: declared here
    kubearmor-dev-next:   668 | void EngineBuilder::setUseOrcMCJITReplacement(bool UseOrcMCJITReplacement) {
    kubearmor-dev-next:       |      ^~~~~~~~~~~~~
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/TypeLoc.h:17,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTTypeTraits.h:24,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTContext.h:18,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/json_map_decl_visitor.cc:20:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h: In static member function ‘static clang::ParamIdx clang::ParamIdx::deserialize(clang::ParamIdx::SerialType)’:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next:   262 |     ParamIdx P(*reinterpret_cast<ParamIdx *>(&S));
    kubearmor-dev-next:       |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next: [ 77%] Building C object src/cc/CMakeFiles/bcc-shared.dir/bcc_elf.c.o
    kubearmor-dev-next: [ 77%] Building C object src/cc/CMakeFiles/bcc-shared.dir/bcc_perf_map.c.o
    kubearmor-dev-next: [ 77%] Building C object src/cc/CMakeFiles/bcc-shared.dir/bcc_proc.c.o
    kubearmor-dev-next: [ 78%] Building CXX object src/cc/CMakeFiles/bcc-shared.dir/common.cc.o
    kubearmor-dev-next: [ 78%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/bcc_btf.cc.o
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bcc_btf.cc: In member function ‘int ebpf::BTF::get_btf_info(const char*, void**, unsigned int*, unsigned int*, void**, unsigned int*, unsigned int*)’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bcc_btf.cc:315:33: warning: ‘int btf_ext__reloc_func_info(const btf*, const btf_ext*, const char*, __u32, void**, __u32*)’ is deprecated: btf_ext__reloc_func_info was never meant as a public API and has wrong assumptions embedded in it; it will be removed in the future libbpf versions [-Wdeprecated-declarations]
    kubearmor-dev-next:   315 |   ret = btf_ext__reloc_func_info(btf_, btf_ext_, fname, 0,
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next:   316 |         func_info, func_info_cnt);
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: In file included from /tmp/build/bcc/src/cc/bcc_libbpf_inc.h:9,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bcc_btf.cc:22:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/libbpf/src/btf.h:88:5: note: declared here
    kubearmor-dev-next:    88 | int btf_ext__reloc_func_info(const struct btf *btf,
    kubearmor-dev-next:       |     ^~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bcc_btf.cc:322:33: warning: ‘int btf_ext__reloc_line_info(const btf*, const btf_ext*, const char*, __u32, void**, __u32*)’ is deprecated: btf_ext__reloc_line_info was never meant as a public API and has wrong assumptions embedded in it; it will be removed in the future libbpf versions [-Wdeprecated-declarations]
    kubearmor-dev-next:   322 |   ret = btf_ext__reloc_line_info(btf_, btf_ext_, fname, 0,
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next:   323 |         line_info, line_info_cnt);
    kubearmor-dev-next:       |         ~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: In file included from /tmp/build/bcc/src/cc/bcc_libbpf_inc.h:9,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bcc_btf.cc:22:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/libbpf/src/btf.h:93:5: note: declared here
    kubearmor-dev-next:    93 | int btf_ext__reloc_line_info(const struct btf *btf,
    kubearmor-dev-next:       |     ^~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: [ 78%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/exported_files.cc.o
    kubearmor-dev-next: [ 79%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/bcc_debug.cc.o
    kubearmor-dev-next: [ 79%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/bpf_module_rw_engine.cc.o
    kubearmor-dev-next: [ 79%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/table_storage.cc.o
    kubearmor-dev-next: [ 80%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/shared_table.cc.o
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc: In member function ‘std::unique_ptr<llvm::ExecutionEngine> ebpf::BPFModule::finalize_rw(std::unique_ptr<llvm::Module>)’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:360:36: warning: ‘void llvm::EngineBuilder::setUseOrcMCJITReplacement(bool)’ is deprecated [-Wdeprecated-declarations]
    kubearmor-dev-next:   360 |   builder.setUseOrcMCJITReplacement(false);
    kubearmor-dev-next:       |   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/llvm/ExecutionEngine/MCJIT.h:17,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:20:
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ExecutionEngine/ExecutionEngine.h:668:6: note: declared here
    kubearmor-dev-next:   668 | void EngineBuilder::setUseOrcMCJITReplacement(bool UseOrcMCJITReplacement) {
    kubearmor-dev-next:       |      ^~~~~~~~~~~~~
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/llvm/ExecutionEngine/ExecutionEngine.h:18,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/llvm/ExecutionEngine/MCJIT.h:17,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:20:
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h: In instantiation of ‘llvm::ArrayRef<T>::ArrayRef(const std::initializer_list<_Tp>&) [with T = llvm::Value*]’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:79:35:   required from here
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h:101:37: warning: initializing ‘llvm::ArrayRef<llvm::Value*>::Data’ from ‘std::initializer_list<llvm::Value*>::begin’ does not extend the lifetime of the underlying array [-Winit-list-lifetime]
    kubearmor-dev-next:   101 |     : Data(Vec.begin() == Vec.end() ? (T*)nullptr : Vec.begin()),
    kubearmor-dev-next:       |            ~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h: In instantiation of ‘llvm::ArrayRef<T>::ArrayRef(const std::initializer_list<_Tp>&) [with T = llvm::Type*]’:
    kubearmor-dev-next: /tmp/build/bcc/src/cc/bpf_module_rw_engine.cc:231:51:   required from here
    kubearmor-dev-next: /usr/lib/llvm-9/include/llvm/ADT/ArrayRef.h:101:37: warning: initializing ‘llvm::ArrayRef<llvm::Type*>::Data’ from ‘std::initializer_list<llvm::Type*>::begin’ does not extend the lifetime of the underlying array [-Winit-list-lifetime]
    kubearmor-dev-next: [ 80%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/bpffs_table.cc.o
    kubearmor-dev-next: [ 80%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/json_map_decl_visitor.cc.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/RecursiveASTVisitor.h:23,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/json_map_decl_visitor.cc:22:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/DeclOpenMP.h:97:1: warning: multi-line comment [-Wcomment]
    kubearmor-dev-next:    97 | /// #pragma omp declare reduction (foo : int,float : omp_out += omp_in) \
    kubearmor-dev-next:       | ^
    kubearmor-dev-next: [ 81%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/common.cc.o
    kubearmor-dev-next: [ 81%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/usdt/usdt.cc.o
    kubearmor-dev-next: [ 81%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/usdt/usdt_args.cc.o
    kubearmor-dev-next: In file included from /usr/lib/llvm-9/include/clang/AST/TypeLoc.h:17,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTTypeTraits.h:24,
    kubearmor-dev-next:                  from /usr/lib/llvm-9/include/clang/AST/ASTContext.h:18,
    kubearmor-dev-next:                  from /tmp/build/bcc/src/cc/json_map_decl_visitor.cc:20:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h: In static member function ‘static clang::ParamIdx clang::ParamIdx::deserialize(clang::ParamIdx::SerialType)’:
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next:   262 |     ParamIdx P(*reinterpret_cast<ParamIdx *>(&S));
    kubearmor-dev-next:       |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: /usr/lib/llvm-9/include/clang/AST/Attr.h:262:17: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
    kubearmor-dev-next: [ 81%] Linking CXX shared library libbcc.so
    kubearmor-dev-next: [ 82%] Building CXX object src/cc/CMakeFiles/bcc-static.dir/bcc_syms.cc.o
    kubearmor-dev-next: [ 82%] Building C object src/cc/CMakeFiles/bcc-static.dir/bcc_elf.c.o
    kubearmor-dev-next: [ 82%] Building C object src/cc/CMakeFiles/bcc-static.dir/bcc_perf_map.c.o
    kubearmor-dev-next: [ 82%] Building C object src/cc/CMakeFiles/bcc-static.dir/bcc_proc.c.o
    kubearmor-dev-next: [ 82%] Built target bcc-shared
    kubearmor-dev-next: Scanning dependencies of target test_libbcc
    kubearmor-dev-next: [ 83%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_c_api.cc.o
    kubearmor-dev-next: [ 83%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_libbcc.cc.o
    kubearmor-dev-next: In file included from /usr/include/string.h:519,
    kubearmor-dev-next:                  from /tmp/build/bcc/tests/cc/test_c_api.cc:19:
    kubearmor-dev-next: In function ‘char* strncpy(char*, const char*, size_t)’,
    kubearmor-dev-next:     inlined from ‘int mntns_func(void*)’ at /tmp/build/bcc/tests/cc/test_c_api.cc:159:10:
    kubearmor-dev-next: /usr/include/x86_64-linux-gnu/bits/string_fortified.h:95:34: warning: ‘char* __builtin_strncpy(char*, const char*, long unsigned int)’ specified bound 1024 equals destination size [-Wstringop-truncation]
    kubearmor-dev-next:    95 |   return __builtin___strncpy_chk (__dest, __src, __len,
    kubearmor-dev-next:       |          ~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next:    96 |                                   __glibc_objsize (__dest));
    kubearmor-dev-next:       |                                   ~~~~~~~~~~~~~~~~~~~~~~~~~
    kubearmor-dev-next: [ 83%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_array_table.cc.o
    kubearmor-dev-next: [ 83%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_bpf_table.cc.o
    kubearmor-dev-next: [ 84%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_cg_storage.cc.o
    kubearmor-dev-next: [ 85%] Linking CXX static library libbcc.a
    kubearmor-dev-next: [ 85%] Built target bcc-static
    kubearmor-dev-next: [ 85%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_hash_table.cc.o
    kubearmor-dev-next: [ 85%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_map_in_map.cc.o
    kubearmor-dev-next: [ 86%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_perf_event.cc.o
    kubearmor-dev-next: [ 86%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_pinned_table.cc.o
    kubearmor-dev-next: [ 86%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_prog_table.cc.o
    kubearmor-dev-next: [ 87%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_queuestack_table.cc.o
    kubearmor-dev-next: [ 87%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_shared_table.cc.o
    kubearmor-dev-next: [ 87%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_sk_storage.cc.o
    kubearmor-dev-next: [ 88%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_sock_table.cc.o
    kubearmor-dev-next: [ 88%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_usdt_args.cc.o
    kubearmor-dev-next: [ 88%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_usdt_probes.cc.o
    kubearmor-dev-next: [ 89%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/utils.cc.o
    kubearmor-dev-next: [ 89%] Building CXX object tests/cc/CMakeFiles/test_libbcc.dir/test_parse_tracepoint.cc.o
    kubearmor-dev-next: Scanning dependencies of target CGroupTest
    kubearmor-dev-next: [ 89%] Building CXX object examples/cpp/CMakeFiles/CGroupTest.dir/CGroupTest.cc.o
    kubearmor-dev-next: Scanning dependencies of target UseExternalMap
    kubearmor-dev-next: [ 90%] Building CXX object examples/cpp/CMakeFiles/UseExternalMap.dir/UseExternalMap.cc.o
    kubearmor-dev-next: Scanning dependencies of target FollyRequestContextSwitch
    kubearmor-dev-next: [ 90%] Building CXX object examples/cpp/CMakeFiles/FollyRequestContextSwitch.dir/FollyRequestContextSwitch.cc.o
    kubearmor-dev-next: [ 90%] Linking CXX executable CGroupTest
    kubearmor-dev-next: [ 90%] Linking CXX executable FollyRequestContextSwitch
    kubearmor-dev-next: [ 90%] Linking CXX executable UseExternalMap
    kubearmor-dev-next: [ 90%] Linking CXX executable test_libbcc
    kubearmor-dev-next: [ 90%] Built target test_libbcc
    kubearmor-dev-next: Scanning dependencies of target SkLocalStorageIterator
    kubearmor-dev-next: [ 90%] Building CXX object examples/cpp/CMakeFiles/SkLocalStorageIterator.dir/SkLocalStorageIterator.cc.o
    kubearmor-dev-next: [ 90%] Linking CXX executable SkLocalStorageIterator
    kubearmor-dev-next: [ 90%] Built target CGroupTest
    kubearmor-dev-next: Scanning dependencies of target HelloWorld
    kubearmor-dev-next: [ 91%] Building CXX object examples/cpp/CMakeFiles/HelloWorld.dir/HelloWorld.cc.o
    kubearmor-dev-next: [ 91%] Linking CXX executable HelloWorld
    kubearmor-dev-next: [ 91%] Built target FollyRequestContextSwitch
    kubearmor-dev-next: Scanning dependencies of target RecordMySQLQuery
    kubearmor-dev-next: [ 91%] Built target UseExternalMap
    kubearmor-dev-next: [ 91%] Building CXX object examples/cpp/CMakeFiles/RecordMySQLQuery.dir/RecordMySQLQuery.cc.o
    kubearmor-dev-next: Scanning dependencies of target CPUDistribution
    kubearmor-dev-next: [ 91%] Building CXX object examples/cpp/CMakeFiles/CPUDistribution.dir/CPUDistribution.cc.o
    kubearmor-dev-next: [ 92%] Linking CXX executable CPUDistribution
    kubearmor-dev-next: [ 93%] Linking CXX executable RecordMySQLQuery
    kubearmor-dev-next: [ 93%] Built target SkLocalStorageIterator
    kubearmor-dev-next: Scanning dependencies of target TaskIterator
    kubearmor-dev-next: [ 93%] Building CXX object examples/cpp/CMakeFiles/TaskIterator.dir/TaskIterator.cc.o
    kubearmor-dev-next: [ 93%] Linking CXX executable TaskIterator
    kubearmor-dev-next: [ 93%] Built target HelloWorld
    kubearmor-dev-next: Scanning dependencies of target KFuncExample
    kubearmor-dev-next: [ 93%] Building CXX object examples/cpp/CMakeFiles/KFuncExample.dir/KFuncExample.cc.o
    kubearmor-dev-next: [ 94%] Linking CXX executable KFuncExample
    kubearmor-dev-next: [ 94%] Built target CPUDistribution
    kubearmor-dev-next: Scanning dependencies of target TCPSendStack
    kubearmor-dev-next: [ 95%] Building CXX object examples/cpp/CMakeFiles/TCPSendStack.dir/TCPSendStack.cc.o
    kubearmor-dev-next: [ 95%] Built target RecordMySQLQuery
    kubearmor-dev-next: Scanning dependencies of target KModRetExample
    kubearmor-dev-next: [ 95%] Building CXX object examples/cpp/CMakeFiles/KModRetExample.dir/KModRetExample.cc.o
    kubearmor-dev-next: [ 95%] Built target TaskIterator
    kubearmor-dev-next: Scanning dependencies of target LLCStat
    kubearmor-dev-next: [ 96%] Building CXX object examples/cpp/CMakeFiles/LLCStat.dir/LLCStat.cc.o
    kubearmor-dev-next: [ 96%] Linking CXX executable KModRetExample
    kubearmor-dev-next: [ 96%] Linking CXX executable TCPSendStack
    kubearmor-dev-next: [ 96%] Linking CXX executable LLCStat
    kubearmor-dev-next: [ 96%] Built target KFuncExample
    kubearmor-dev-next: Scanning dependencies of target RandomRead
    kubearmor-dev-next: [ 97%] Building CXX object examples/cpp/CMakeFiles/RandomRead.dir/RandomRead.cc.o
    kubearmor-dev-next: [ 97%] Linking CXX executable RandomRead
    kubearmor-dev-next: [ 97%] Built target TCPSendStack
    kubearmor-dev-next: Scanning dependencies of target PyPerf
    kubearmor-dev-next: [ 97%] Building CXX object examples/cpp/pyperf/CMakeFiles/PyPerf.dir/PyPerf.cc.o
    kubearmor-dev-next: [ 97%] Built target KModRetExample
    kubearmor-dev-next: Scanning dependencies of target test_static
    kubearmor-dev-next: [ 98%] Building C object tests/cc/CMakeFiles/test_static.dir/test_static.c.o
    kubearmor-dev-next: [ 98%] Linking CXX executable test_static
    kubearmor-dev-next: [ 98%] Built target LLCStat
    kubearmor-dev-next: [ 99%] Building CXX object examples/cpp/pyperf/CMakeFiles/PyPerf.dir/PyPerfUtil.cc.o
    kubearmor-dev-next: [ 99%] Building CXX object examples/cpp/pyperf/CMakeFiles/PyPerf.dir/PyPerfBPFProgram.cc.o
    kubearmor-dev-next: [ 99%] Building CXX object examples/cpp/pyperf/CMakeFiles/PyPerf.dir/PyPerfLoggingHelper.cc.o
    kubearmor-dev-next: [100%] Building CXX object examples/cpp/pyperf/CMakeFiles/PyPerf.dir/PyPerfDefaultPrinter.cc.o
    kubearmor-dev-next: [100%] Building CXX object examples/cpp/pyperf/CMakeFiles/PyPerf.dir/Py36Offsets.cc.o
    kubearmor-dev-next: [100%] Linking CXX executable PyPerf
    kubearmor-dev-next: [100%] Built target RandomRead
    kubearmor-dev-next: [100%] Built target test_static
    kubearmor-dev-next: [100%] Built target PyPerf
    kubearmor-dev-next: [  8%] Built target bpf-static
    kubearmor-dev-next: [ 10%] Built target clang_frontend
    kubearmor-dev-next: [ 12%] Built target bcc-loader-static
    kubearmor-dev-next: [ 13%] Built target api-static
    kubearmor-dev-next: [ 14%] Built target usdt-static
    kubearmor-dev-next: [ 18%] Built target b_frontend
    kubearmor-dev-next: [ 24%] Built target bcc-static
    kubearmor-dev-next: [ 33%] Built target bpf-shared
    kubearmor-dev-next: [ 38%] Built target bcc-shared
    kubearmor-dev-next: [ 38%] Built target bcc_py_python3
    kubearmor-dev-next: [ 39%] Built target bps
    kubearmor-dev-next: [ 39%] Built target CGroupTest
    kubearmor-dev-next: [ 40%] Built target UseExternalMap
    kubearmor-dev-next: [ 40%] Built target FollyRequestContextSwitch
    kubearmor-dev-next: [ 40%] Built target SkLocalStorageIterator
    kubearmor-dev-next: [ 41%] Built target HelloWorld
    kubearmor-dev-next: [ 42%] Built target RecordMySQLQuery
    kubearmor-dev-next: [ 43%] Built target CPUDistribution
    kubearmor-dev-next: [ 43%] Built target TaskIterator
    kubearmor-dev-next: [ 44%] Built target KFuncExample
    kubearmor-dev-next: [ 45%] Built target TCPSendStack
    kubearmor-dev-next: [ 45%] Built target KModRetExample
    kubearmor-dev-next: [ 46%] Built target LLCStat
    kubearmor-dev-next: [ 47%] Built target RandomRead
    kubearmor-dev-next: [ 49%] Built target PyPerf
    kubearmor-dev-next: [ 92%] Built target man
    kubearmor-dev-next: [ 93%] Built target usdt_test_lib
    kubearmor-dev-next: [ 99%] Built target test_libbcc
    kubearmor-dev-next: [100%] Built target test_static
    kubearmor-dev-next: Install the project...
    kubearmor-dev-next: -- Install configuration: "Release"
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc.so.0.22.0
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc.so.0
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc.so
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc.a
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc-loader-static.a
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc_bpf.a
    kubearmor-dev-next: -- Installing: /usr/include/bcc/file_desc.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/table_desc.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/table_storage.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bcc_common.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bpf_module.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bcc_exception.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bcc_syms.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bcc_proc.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bcc_elf.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bcc_usdt.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/netlink.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/pkt_cls.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/if_xdp.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/pkt_sched.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/btf.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/if_link.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/bpf.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/compat/linux/bpf_common.h
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/pkgconfig/libbcc.pc
    kubearmor-dev-next: -- Installing: /usr/include/bcc/libbpf.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/perf_reader.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/bcc_version.h
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc_bpf.so.0.22.0
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc_bpf.so.0
    kubearmor-dev-next: -- Installing: /usr/lib/x86_64-linux-gnu/libbcc_bpf.so
    kubearmor-dev-next: -- Installing: /usr/include/bcc/BPF.h
    kubearmor-dev-next: -- Installing: /usr/include/bcc/BPFTable.h
    kubearmor-dev-next: running install
    kubearmor-dev-next: running build
    kubearmor-dev-next: running build_py
    kubearmor-dev-next: creating build
    kubearmor-dev-next: creating build/lib
    kubearmor-dev-next: creating build/lib/bcc
    kubearmor-dev-next: copying bcc/syscall.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/perf.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/table.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/version.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/utils.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/usdt.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/containers.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/__init__.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/libbcc.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/tcp.py -> build/lib/bcc
    kubearmor-dev-next: copying bcc/disassembler.py -> build/lib/bcc
    kubearmor-dev-next: running install_lib
    kubearmor-dev-next: creating /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/syscall.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/perf.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/table.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/version.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/utils.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/usdt.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/containers.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/__init__.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/libbcc.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/tcp.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: copying build/lib/bcc/disassembler.py -> /usr/lib/python3/dist-packages/bcc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/syscall.py to syscall.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/perf.py to perf.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/table.py to table.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/version.py to version.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/utils.py to utils.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/usdt.py to usdt.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/containers.py to containers.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/__init__.py to __init__.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/libbcc.py to libbcc.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/tcp.py to tcp.cpython-39.pyc
    kubearmor-dev-next: byte-compiling /usr/lib/python3/dist-packages/bcc/disassembler.py to disassembler.cpython-39.pyc
    kubearmor-dev-next: running install_egg_info
    kubearmor-dev-next: Writing /usr/lib/python3/dist-packages/bcc-0.22.0_bced75aa.egg-info
    kubearmor-dev-next: -- Installing: /usr/share/bcc/introspection/bps
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/hello_world.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/bashreadline.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/bashreadline.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/kprobe-latency.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/kprobe-write.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/memleak.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/offcputime.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/sock-parse-dns.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/sock-parse-http.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/sock-proto.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/sock-protolen.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/strlen_count.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/task_switch.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/tracepoint-offcputime.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/uprobe-readline-perf.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/uprobe-readline.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/uprobe-tailkt.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/lua/usdt_ruby.lua
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/simulation.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/simple_tc.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tc_perf_event.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/distributed_bridge/simulation.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/distributed_bridge/tunnel.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/distributed_bridge/tunnel_mesh.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/distributed_bridge/main.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/distributed_bridge/tunnel_mesh.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/distributed_bridge/tunnel.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/neighbor_sharing/README.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/neighbor_sharing/simulation.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/neighbor_sharing/tc_neighbor_sharing.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/neighbor_sharing/tc_neighbor_sharing.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/vlan_learning/README.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/vlan_learning/simulation.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/vlan_learning/vlan_learning.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/vlan_learning/vlan_learning.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/README.md
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/chord.png
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/monitor.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/simulation.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/vxlan.jpg
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/main.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/monitor.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/setup.sh
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/tunnel_monitor/traffic.sh
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/http_filter/http-parse-complete.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/http_filter/http-parse-simple.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/http_filter/README.md
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/http_filter/http-parse-complete.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/http_filter/http-parse-simple.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/xdp/xdp_drop_count.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/xdp/xdp_macswap_count.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/xdp/xdp_redirect_cpu.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/networking/xdp/xdp_redirect_map.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/biolatpcts.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/bitehist.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/dddos.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/disksnoop.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/hello_fields.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/hello_perf_output.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/hello_perf_output_using_ns.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/kvm_hypercall.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/mallocstacks.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/mysqld_query.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/nflatency.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/nodejs_http_server.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/stack_buildid_example.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/stacksnoop.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/strlen_count.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/strlen_hist.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/strlen_hist_ifunc.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/strlen_snoop.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/sync_timing.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/task_switch.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/tcpv4connect.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/trace_fields.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/trace_perf_output.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/undump.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/urandomread-explicit.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/urandomread.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/vfsreadlat.py
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/task_switch.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/vfsreadlat.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/CMakeLists.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/biolatpcts_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/bitehist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/dddos_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/disksnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/kvm_hypercall.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/mysqld_query_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/nodejs_http_server_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/stacksnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/tcpv4connect_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/urandomread_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/examples/tracing/vfsreadlat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/argdist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/bashreadline.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/bindsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/biolatency.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/biolatpcts.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/biosnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/biotop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/bitesize.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/bpflist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/bps.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/btrfsdist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/btrfsslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/cachestat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/cachetop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/capable.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/cobjnew.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/compactsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/cpudist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/cpuunclaimed.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/criticalstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/cthreads.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/dbslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/dbstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/dcsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/dcstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/deadlock.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/dirtop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/drsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/execsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/exitsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/ext4dist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/ext4slower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/filelife.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/fileslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/filetop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/funccount.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/funcinterval.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/funclatency.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/funcslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/gethostlatency.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/hardirqs.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/inject.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/javacalls.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/javaflow.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/javagc.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/javaobjnew.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/javastat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/javathreads.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/killsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/klockstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/ksnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/kvmexit.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/llcstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/mdflush.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/memleak.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/mountsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/mysqld_qslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/netqtop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/nfsdist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/nfsslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/nodegc.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/nodestat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/offcputime.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/offwaketime.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/oomkill.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/opensnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/perlcalls.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/perlflow.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/perlstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/phpcalls.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/phpflow.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/phpstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/pidpersec.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/profile.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/pythoncalls.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/pythonflow.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/pythongc.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/pythonstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/readahead.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/reset-trace.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/rubycalls.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/rubyflow.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/rubygc.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/rubyobjnew.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/rubystat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/runqlat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/runqlen.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/runqslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/shmsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/slabratetop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/sofdsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/softirqs.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/solisten.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/spfdsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/sslsniff.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/stackcount.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/statsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/swapin.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/syncsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/syscount.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tclcalls.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tclflow.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tclobjnew.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tclstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpaccept.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpconnect.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpconnlat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpdrop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcplife.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpretrans.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcprtt.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpstates.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpsubnet.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcpsynbl.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcptop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tcptracer.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/threadsnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/tplist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/trace.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/ttysnoop.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/ucalls.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/uflow.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/ugc.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/uobjnew.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/ustat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/uthreads.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/vfscount.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/vfsstat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/virtiostat.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/wakeuptime.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/xfsdist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/xfsslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/zfsdist.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/man/man8/zfsslower.8.gz
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/argdist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/bashreadline
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/bindsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/biolatency
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/biolatpcts
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/biosnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/biotop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/bitesize
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/bpflist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/btrfsdist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/btrfsslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/cachestat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/cachetop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/capable
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/compactsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/cpudist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/cpuunclaimed
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/criticalstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/dbslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/dbstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/dcsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/dcstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/deadlock
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/dirtop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/drsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/execsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/exitsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/ext4dist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/ext4slower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/filelife
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/fileslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/filetop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/funccount
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/funcinterval
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/funclatency
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/funcslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/gethostlatency
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/hardirqs
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/inject
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/killsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/klockstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/kvmexit
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/llcstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/mdflush
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/memleak
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/mountsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/mysqld_qslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/netqtop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/nfsdist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/nfsslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/offcputime
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/offwaketime
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/oomkill
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/opensnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/pidpersec
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/profile
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/readahead
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/runqlat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/runqlen
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/runqslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/shmsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/slabratetop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/sofdsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/softirqs
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/solisten
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/sslsniff
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/stackcount
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/statsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/swapin
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/syncsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/syscount
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpaccept
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpconnect
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpconnlat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpdrop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcplife
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpretrans
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcprtt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpstates
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpsubnet
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcpsynbl
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcptop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tcptracer
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/threadsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tplist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/trace
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/ttysnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/vfscount
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/vfsstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/virtiostat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/wakeuptime
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/xfsdist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/xfsslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/zfsdist
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/zfsslower
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/cobjnew
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/javacalls
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/javaflow
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/javagc
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/javaobjnew
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/javastat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/javathreads
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/nodegc
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/nodestat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/perlcalls
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/perlflow
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/perlstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/phpcalls
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/phpflow
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/phpstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/pythoncalls
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/pythonflow
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/pythongc
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/pythonstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/reset-trace
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/rubycalls
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/rubyflow
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/rubygc
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/rubyobjnew
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/rubystat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tclcalls
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tclflow
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tclobjnew
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/tclstat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/deadlock.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/netqtop.c
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/argdist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/bashreadline_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/bindsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/biolatency_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/biolatpcts_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/biosnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/biotop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/bitesize_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/bpflist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/btrfsdist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/btrfsslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/cachestat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/cachetop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/capable_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/cobjnew_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/compactsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/cpudist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/cpuunclaimed_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/criticalstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/cthreads_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/dbslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/dbstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/dcsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/dcstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/deadlock_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/dirtop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/drsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/execsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/exitsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/ext4dist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/ext4slower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/filelife_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/fileslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/filetop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/funccount_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/funcinterval_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/funclatency_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/funcslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/gethostlatency_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/hardirqs_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/inject_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/javacalls_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/javaflow_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/javagc_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/javaobjnew_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/javastat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/javathreads_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/killsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/klockstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/kvmexit_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/llcstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/mdflush_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/memleak_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/mountsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/mysqld_qslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/netqtop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/nfsdist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/nfsslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/nodegc_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/nodestat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/offcputime_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/offwaketime_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/oomkill_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/opensnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/perlcalls_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/perlflow_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/perlstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/phpcalls_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/phpflow_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/phpstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/pidpersec_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/profile_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/pythoncalls_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/pythonflow_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/pythongc_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/pythonstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/readahead_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/reset-trace_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/rubycalls_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/rubyflow_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/rubygc_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/rubyobjnew_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/rubystat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/runqlat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/runqlen_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/runqslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/shmsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/slabratetop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/sofdsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/softirqs_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/solisten_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/sslsniff_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/stackcount_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/statsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/swapin_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/syncsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/syscount_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tclcalls_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tclflow_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tclobjnew_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tclstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpaccept_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpconnect_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpconnlat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpdrop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcplife_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpretrans_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcprtt_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpstates_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpsubnet_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcpsynbl_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcptop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tcptracer_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/threadsnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/tplist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/trace_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/ttysnoop_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/vfscount_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/vfsstat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/virtiostat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/wakeuptime_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/xfsdist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/xfsslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/zfsdist_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/zfsslower_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/lib/ucalls
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/lib/uflow
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/lib/ugc
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/lib/uobjnew
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/lib/ustat
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/lib/uthreads
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/lib/ucalls_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/lib/uflow_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/lib/ugc_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/lib/uobjnew_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/lib/ustat_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/doc/lib/uthreads_example.txt
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/bashreadline
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/biosnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/compactsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/filelife
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/gethostlatency
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/hardirqs
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/killsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/memleak
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/offcputime
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/offwaketime
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/oomkill
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/opensnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/profile
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/softirqs
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/stackcount
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/stacksnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/statsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/syncsnoop
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/tcpaccept
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/tcpconnect
    kubearmor-dev-next: -- Installing: /usr/share/bcc/tools/old/wakeuptime
    kubearmor-dev-next: Installing golang binaries...
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: apparmor is already the newest version (3.0.3-0ubuntu1).
    kubearmor-dev-next: apparmor set to manually installed.
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: The following additional packages will be installed:
    kubearmor-dev-next:   libauparse0 python3-apparmor python3-libapparmor
    kubearmor-dev-next: Suggested packages:
    kubearmor-dev-next:   vim-addon-manager audispd-plugins
    kubearmor-dev-next: The following NEW packages will be installed:
    kubearmor-dev-next:   apparmor-utils auditd libauparse0 python3-apparmor python3-libapparmor
    kubearmor-dev-next: 0 upgraded, 5 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Need to get 402 kB of archives.
    kubearmor-dev-next: After this operation, 1830 kB of additional disk space will be used.
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish/main amd64 libauparse0 amd64 1:3.0-2ubuntu2 [49.8 kB]
    kubearmor-dev-next: Get:2 http://archive.ubuntu.com/ubuntu impish/main amd64 auditd amd64 1:3.0-2ubuntu2 [192 kB]
    kubearmor-dev-next: Get:3 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-libapparmor amd64 3.0.3-0ubuntu1 [29.4 kB]
    kubearmor-dev-next: Get:4 http://archive.ubuntu.com/ubuntu impish/main amd64 python3-apparmor amd64 3.0.3-0ubuntu1 [78.9 kB]
    kubearmor-dev-next: Get:5 http://archive.ubuntu.com/ubuntu impish/main amd64 apparmor-utils amd64 3.0.3-0ubuntu1 [51.8 kB]
    kubearmor-dev-next: dpkg-preconfigure: unable to re-open stdin: No such file or directory
    kubearmor-dev-next: Fetched 402 kB in 1s (616 kB/s)
    kubearmor-dev-next: Selecting previously unselected package libauparse0:amd64.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 106217 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../libauparse0_1%3a3.0-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking libauparse0:amd64 (1:3.0-2ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package auditd.
    kubearmor-dev-next: Preparing to unpack .../auditd_1%3a3.0-2ubuntu2_amd64.deb ...
    kubearmor-dev-next: Unpacking auditd (1:3.0-2ubuntu2) ...
    kubearmor-dev-next: Selecting previously unselected package python3-libapparmor.
    kubearmor-dev-next: Preparing to unpack .../python3-libapparmor_3.0.3-0ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-libapparmor (3.0.3-0ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package python3-apparmor.
    kubearmor-dev-next: Preparing to unpack .../python3-apparmor_3.0.3-0ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking python3-apparmor (3.0.3-0ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package apparmor-utils.
    kubearmor-dev-next: Preparing to unpack .../apparmor-utils_3.0.3-0ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking apparmor-utils (3.0.3-0ubuntu1) ...
    kubearmor-dev-next: Setting up python3-libapparmor (3.0.3-0ubuntu1) ...
    kubearmor-dev-next: Setting up libauparse0:amd64 (1:3.0-2ubuntu2) ...
    kubearmor-dev-next: Setting up python3-apparmor (3.0.3-0ubuntu1) ...
    kubearmor-dev-next: Setting up auditd (1:3.0-2ubuntu2) ...
    kubearmor-dev-next: Created symlink /etc/systemd/system/multi-user.target.wants/auditd.service → /lib/systemd/system/auditd.service.
    kubearmor-dev-next: Setting up apparmor-utils (3.0.3-0ubuntu1) ...
    kubearmor-dev-next: Processing triggers for man-db (2.9.4-2) ...
    kubearmor-dev-next: Processing triggers for libc-bin (2.34-0ubuntu3) ...
    kubearmor-dev-next: 
    kubearmor-dev-next: Running kernel seems to be up-to-date.
    kubearmor-dev-next: 
    kubearmor-dev-next: No services need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No containers need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No user sessions are running outdated binaries.
    kubearmor-dev-next: Synchronizing state of auditd.service with SysV service script with /lib/systemd/systemd-sysv-install.
    kubearmor-dev-next: Executing: /lib/systemd/systemd-sysv-install enable auditd
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: Suggested packages:
    kubearmor-dev-next:   zip
    kubearmor-dev-next: The following NEW packages will be installed:
    kubearmor-dev-next:   unzip
    kubearmor-dev-next: 0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Need to get 168 kB of archives.
    kubearmor-dev-next: After this operation, 401 kB of additional disk space will be used.
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish/main amd64 unzip amd64 6.0-26ubuntu1 [168 kB]
    kubearmor-dev-next: dpkg-preconfigure: unable to re-open stdin: No such file or directory
    kubearmor-dev-next: Fetched 168 kB in 0s (549 kB/s)
    kubearmor-dev-next: Selecting previously unselected package unzip.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 106386 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../unzip_6.0-26ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking unzip (6.0-26ubuntu1) ...
    kubearmor-dev-next: Setting up unzip (6.0-26ubuntu1) ...
    kubearmor-dev-next: Processing triggers for man-db (2.9.4-2) ...
    kubearmor-dev-next: 
    kubearmor-dev-next: Running kernel seems to be up-to-date.
    kubearmor-dev-next: 
    kubearmor-dev-next: No services need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No containers need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No user sessions are running outdated binaries.
    kubearmor-dev-next: Archive:  protoc-3.14.0-linux-x86_64.zip
    kubearmor-dev-next:    creating: include/
    kubearmor-dev-next:    creating: include/google/
    kubearmor-dev-next:    creating: include/google/protobuf/
    kubearmor-dev-next:   inflating: include/google/protobuf/wrappers.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/field_mask.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/api.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/struct.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/descriptor.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/timestamp.proto
    kubearmor-dev-next:    creating: include/google/protobuf/compiler/
    kubearmor-dev-next:   inflating: include/google/protobuf/compiler/plugin.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/empty.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/any.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/source_context.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/type.proto
    kubearmor-dev-next:   inflating: include/google/protobuf/duration.proto
    kubearmor-dev-next:    creating: bin/
    kubearmor-dev-next:   inflating: bin/protoc
    kubearmor-dev-next:   inflating: readme.txt
    kubearmor-dev-next: go: downloading google.golang.org/grpc v1.41.0
    kubearmor-dev-next: go: downloading golang.org/x/net v0.0.0-20200822124328-c89045814202
    kubearmor-dev-next: go: downloading github.com/golang/protobuf v1.4.3
    kubearmor-dev-next: go: downloading golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd
    kubearmor-dev-next: go: downloading github.com/golang/protobuf v1.5.2
    kubearmor-dev-next: go: downloading golang.org/x/net v0.0.0-20211020060615-d418f374d309
    kubearmor-dev-next: go: downloading google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013
    kubearmor-dev-next: go: downloading golang.org/x/sys v0.0.0-20211020174200-9d6173849985
    kubearmor-dev-next: go: downloading google.golang.org/protobuf v1.25.0
    kubearmor-dev-next: go: downloading google.golang.org/protobuf v1.27.1
    kubearmor-dev-next: go: downloading golang.org/x/text v0.3.0
    kubearmor-dev-next: go: downloading google.golang.org/genproto v0.0.0-20211020151524-b7c3a969101a
    kubearmor-dev-next: go: downloading golang.org/x/text v0.3.7
    kubearmor-dev-next: go: downloading google.golang.org/protobuf v1.26.0
    kubearmor-dev-next: go: module github.com/golang/protobuf is deprecated: Use the "google.golang.org/protobuf" module instead.
    kubearmor-dev-next: go get: installing executables with 'go get' in module mode is deprecated.
    kubearmor-dev-next: 	Use 'go install pkg@version' instead.
    kubearmor-dev-next: 	For more information, see https://golang.org/doc/go-get-install-deprecation
    kubearmor-dev-next: 	or run 'go help get' or 'go help install'.
    kubearmor-dev-next: {Version:kustomize/v4.4.0 GitCommit:63ec6bdb3d737a7c66901828c5743656c49b60e1 BuildDate:2021-09-27T16:24:12Z GoOs:linux GoArch:amd64}
    kubearmor-dev-next: kustomize installed to /tmp/build/kustomize
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: /tmp/vagrant-shell20211020-109471-obolf1.sh
    kubearmor-dev-next: Hit:1 http://archive.ubuntu.com/ubuntu impish InRelease
    kubearmor-dev-next: Hit:2 http://archive.ubuntu.com/ubuntu impish-updates InRelease
    kubearmor-dev-next: Hit:3 http://archive.ubuntu.com/ubuntu impish-backports InRelease
    kubearmor-dev-next: Hit:4 http://security.ubuntu.com/ubuntu impish-security InRelease
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: curl is already the newest version (7.74.0-1.3ubuntu2).
    kubearmor-dev-next: curl set to manually installed.
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).
    kubearmor-dev-next: OK
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: software-properties-common is already the newest version (0.99.13).
    kubearmor-dev-next: software-properties-common set to manually installed.
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Hit:1 http://archive.ubuntu.com/ubuntu impish InRelease
    kubearmor-dev-next: Hit:2 http://archive.ubuntu.com/ubuntu impish-updates InRelease
    kubearmor-dev-next: Hit:3 http://archive.ubuntu.com/ubuntu impish-backports InRelease
    kubearmor-dev-next: Get:4 https://download.docker.com/linux/ubuntu focal InRelease [57.7 kB]
    kubearmor-dev-next: Hit:5 http://security.ubuntu.com/ubuntu impish-security InRelease
    kubearmor-dev-next: Get:6 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages [11.6 kB]
    kubearmor-dev-next: Fetched 69.3 kB in 1s (137 kB/s)
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Repository: 'deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable'
    kubearmor-dev-next: Description:
    kubearmor-dev-next: Archive for codename: focal components: stable
    kubearmor-dev-next: More info: https://download.docker.com/linux/ubuntu
    kubearmor-dev-next: Adding repository.
    kubearmor-dev-next: Adding deb entry to /etc/apt/sources.list.d/archive_uri-https_download_docker_com_linux_ubuntu-impish.list
    kubearmor-dev-next: Adding disabled deb-src entry to /etc/apt/sources.list.d/archive_uri-https_download_docker_com_linux_ubuntu-impish.list
    kubearmor-dev-next: Hit:1 http://archive.ubuntu.com/ubuntu impish InRelease
    kubearmor-dev-next: Hit:2 http://archive.ubuntu.com/ubuntu impish-updates InRelease
    kubearmor-dev-next: Hit:3 https://download.docker.com/linux/ubuntu focal InRelease
    kubearmor-dev-next: Hit:4 http://archive.ubuntu.com/ubuntu impish-backports InRelease
    kubearmor-dev-next: Hit:5 http://security.ubuntu.com/ubuntu impish-security InRelease
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: docker-ce:
    kubearmor-dev-next:   Installed: (none)
    kubearmor-dev-next:   Candidate: 5:20.10.9~3-0~ubuntu-focal
    kubearmor-dev-next:   Version table:
    kubearmor-dev-next:      5:20.10.9~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.8~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.7~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.6~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.5~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.4~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.3~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.2~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.1~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:20.10.0~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:19.03.15~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:19.03.14~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:19.03.13~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:19.03.12~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:19.03.11~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:19.03.10~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next:      5:19.03.9~3-0~ubuntu-focal 500
    kubearmor-dev-next:         500 https://download.docker.com/linux/ubuntu focal/stable amd64 Packages
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: The following additional packages will be installed:
    kubearmor-dev-next:   containerd.io docker-ce-cli docker-ce-rootless-extras docker-scan-plugin
    kubearmor-dev-next:   libltdl7 libslirp0 pigz slirp4netns
    kubearmor-dev-next: Suggested packages:
    kubearmor-dev-next:   aufs-tools cgroupfs-mount | cgroup-lite
    kubearmor-dev-next: The following NEW packages will be installed:
    kubearmor-dev-next:   containerd.io docker-ce docker-ce-cli docker-ce-rootless-extras
    kubearmor-dev-next:   docker-scan-plugin libltdl7 libslirp0 pigz slirp4netns
    kubearmor-dev-next: 0 upgraded, 9 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Need to get 95.7 MB of archives.
    kubearmor-dev-next: After this operation, 404 MB of additional disk space will be used.
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish/universe amd64 pigz amd64 2.6-1 [63.6 kB]
    kubearmor-dev-next: Get:2 https://download.docker.com/linux/ubuntu focal/stable amd64 containerd.io amd64 1.4.11-1 [23.7 MB]
    kubearmor-dev-next: Get:3 http://archive.ubuntu.com/ubuntu impish/main amd64 libltdl7 amd64 2.4.6-15 [38.8 kB]
    kubearmor-dev-next: Get:4 http://archive.ubuntu.com/ubuntu impish/main amd64 libslirp0 amd64 4.4.0-1build1 [57.7 kB]
    kubearmor-dev-next: Get:5 http://archive.ubuntu.com/ubuntu impish/universe amd64 slirp4netns amd64 1.0.1-2 [28.2 kB]
    kubearmor-dev-next: Get:6 https://download.docker.com/linux/ubuntu focal/stable amd64 docker-ce-cli amd64 5:20.10.9~3-0~ubuntu-focal [38.8 MB]
    kubearmor-dev-next: Get:7 https://download.docker.com/linux/ubuntu focal/stable amd64 docker-ce amd64 5:20.10.9~3-0~ubuntu-focal [21.2 MB]
    kubearmor-dev-next: Get:8 https://download.docker.com/linux/ubuntu focal/stable amd64 docker-ce-rootless-extras amd64 5:20.10.9~3-0~ubuntu-focal [7914 kB]
    kubearmor-dev-next: Get:9 https://download.docker.com/linux/ubuntu focal/stable amd64 docker-scan-plugin amd64 0.8.0~ubuntu-focal [3889 kB]
    kubearmor-dev-next: dpkg-preconfigure: unable to re-open stdin: No such file or directory
    kubearmor-dev-next: Fetched 95.7 MB in 1min 12s (1327 kB/s)
    kubearmor-dev-next: Selecting previously unselected package pigz.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 106404 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../0-pigz_2.6-1_amd64.deb ...
    kubearmor-dev-next: Unpacking pigz (2.6-1) ...
    kubearmor-dev-next: Selecting previously unselected package containerd.io.
    kubearmor-dev-next: Preparing to unpack .../1-containerd.io_1.4.11-1_amd64.deb ...
    kubearmor-dev-next: Unpacking containerd.io (1.4.11-1) ...
    kubearmor-dev-next: Selecting previously unselected package docker-ce-cli.
    kubearmor-dev-next: Preparing to unpack .../2-docker-ce-cli_5%3a20.10.9~3-0~ubuntu-focal_amd64.deb ...
    kubearmor-dev-next: Unpacking docker-ce-cli (5:20.10.9~3-0~ubuntu-focal) ...
    kubearmor-dev-next: Selecting previously unselected package docker-ce.
    kubearmor-dev-next: Preparing to unpack .../3-docker-ce_5%3a20.10.9~3-0~ubuntu-focal_amd64.deb ...
    kubearmor-dev-next: Unpacking docker-ce (5:20.10.9~3-0~ubuntu-focal) ...
    kubearmor-dev-next: Selecting previously unselected package docker-ce-rootless-extras.
    kubearmor-dev-next: Preparing to unpack .../4-docker-ce-rootless-extras_5%3a20.10.9~3-0~ubuntu-focal_amd64.deb ...
    kubearmor-dev-next: Unpacking docker-ce-rootless-extras (5:20.10.9~3-0~ubuntu-focal) ...
    kubearmor-dev-next: Selecting previously unselected package docker-scan-plugin.
    kubearmor-dev-next: Preparing to unpack .../5-docker-scan-plugin_0.8.0~ubuntu-focal_amd64.deb ...
    kubearmor-dev-next: Unpacking docker-scan-plugin (0.8.0~ubuntu-focal) ...
    kubearmor-dev-next: Selecting previously unselected package libltdl7:amd64.
    kubearmor-dev-next: Preparing to unpack .../6-libltdl7_2.4.6-15_amd64.deb ...
    kubearmor-dev-next: Unpacking libltdl7:amd64 (2.4.6-15) ...
    kubearmor-dev-next: Selecting previously unselected package libslirp0:amd64.
    kubearmor-dev-next: Preparing to unpack .../7-libslirp0_4.4.0-1build1_amd64.deb ...
    kubearmor-dev-next: Unpacking libslirp0:amd64 (4.4.0-1build1) ...
    kubearmor-dev-next: Selecting previously unselected package slirp4netns.
    kubearmor-dev-next: Preparing to unpack .../8-slirp4netns_1.0.1-2_amd64.deb ...
    kubearmor-dev-next: Unpacking slirp4netns (1.0.1-2) ...
    kubearmor-dev-next: Setting up docker-scan-plugin (0.8.0~ubuntu-focal) ...
    kubearmor-dev-next: Setting up containerd.io (1.4.11-1) ...
    kubearmor-dev-next: Created symlink /etc/systemd/system/multi-user.target.wants/containerd.service → /lib/systemd/system/containerd.service.
    kubearmor-dev-next: Setting up libltdl7:amd64 (2.4.6-15) ...
    kubearmor-dev-next: Setting up docker-ce-cli (5:20.10.9~3-0~ubuntu-focal) ...
    kubearmor-dev-next: Setting up libslirp0:amd64 (4.4.0-1build1) ...
    kubearmor-dev-next: Setting up pigz (2.6-1) ...
    kubearmor-dev-next: Setting up docker-ce-rootless-extras (5:20.10.9~3-0~ubuntu-focal) ...
    kubearmor-dev-next: Setting up slirp4netns (1.0.1-2) ...
    kubearmor-dev-next: Setting up docker-ce (5:20.10.9~3-0~ubuntu-focal) ...
    kubearmor-dev-next: Created symlink /etc/systemd/system/multi-user.target.wants/docker.service → /lib/systemd/system/docker.service.
    kubearmor-dev-next: Created symlink /etc/systemd/system/sockets.target.wants/docker.socket → /lib/systemd/system/docker.socket.
    kubearmor-dev-next: Processing triggers for man-db (2.9.4-2) ...
    kubearmor-dev-next: Processing triggers for libc-bin (2.34-0ubuntu3) ...
    kubearmor-dev-next: 
    kubearmor-dev-next: Running kernel seems to be up-to-date.
    kubearmor-dev-next: 
    kubearmor-dev-next: No services need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No containers need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No user sessions are running outdated binaries.
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: /tmp/vagrant-shell20211020-109471-104gfuj.sh
    kubearmor-dev-next: Hit:1 http://archive.ubuntu.com/ubuntu impish InRelease
    kubearmor-dev-next: Hit:2 https://download.docker.com/linux/ubuntu focal InRelease
    kubearmor-dev-next: Hit:3 http://archive.ubuntu.com/ubuntu impish-updates InRelease
    kubearmor-dev-next: Hit:4 http://archive.ubuntu.com/ubuntu impish-backports InRelease
    kubearmor-dev-next: Hit:5 http://security.ubuntu.com/ubuntu impish-security InRelease
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: The following NEW packages will be installed:
    kubearmor-dev-next:   apt-transport-https
    kubearmor-dev-next: 0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Need to get 1510 B of archives.
    kubearmor-dev-next: After this operation, 167 kB of additional disk space will be used.
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish/universe amd64 apt-transport-https all 2.3.9 [1510 B]
    kubearmor-dev-next: dpkg-preconfigure: unable to re-open stdin: No such file or directory
    kubearmor-dev-next: Fetched 1510 B in 0s (11.2 kB/s)
    kubearmor-dev-next: Selecting previously unselected package apt-transport-https.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 106667 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../apt-transport-https_2.3.9_all.deb ...
    kubearmor-dev-next: Unpacking apt-transport-https (2.3.9) ...
    kubearmor-dev-next: Setting up apt-transport-https (2.3.9) ...
    kubearmor-dev-next: 
    kubearmor-dev-next: Running kernel seems to be up-to-date.
    kubearmor-dev-next: 
    kubearmor-dev-next: No services need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No containers need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No user sessions are running outdated binaries.
    kubearmor-dev-next: Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).
    kubearmor-dev-next: Executing: /tmp/apt-key-gpghome.H4lPyEQW6L/gpg.1.sh --recv-keys --keyserver keyserver.ubuntu.com 3746C208A7317B0F
    kubearmor-dev-next: gpg: key 3746C208A7317B0F: public key "Google Cloud Packages Automatic Signing Key <gc-team@google.com>" imported
    kubearmor-dev-next: gpg: Total number processed: 1
    kubearmor-dev-next: gpg:               imported: 1
    kubearmor-dev-next: Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).
    kubearmor-dev-next: OK
    kubearmor-dev-next: deb http://apt.kubernetes.io/ kubernetes-xenial main
    kubearmor-dev-next: Hit:1 http://archive.ubuntu.com/ubuntu impish InRelease
    kubearmor-dev-next: Hit:2 http://archive.ubuntu.com/ubuntu impish-updates InRelease
    kubearmor-dev-next: Hit:3 https://download.docker.com/linux/ubuntu focal InRelease
    kubearmor-dev-next: Hit:4 http://archive.ubuntu.com/ubuntu impish-backports InRelease
    kubearmor-dev-next: Hit:6 http://security.ubuntu.com/ubuntu impish-security InRelease
    kubearmor-dev-next: Get:5 https://packages.cloud.google.com/apt kubernetes-xenial InRelease [9383 B]
    kubearmor-dev-next: Get:7 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 Packages [50.0 kB]
    kubearmor-dev-next: Fetched 59.4 kB in 1s (44.1 kB/s)
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: The following additional packages will be installed:
    kubearmor-dev-next:   conntrack cri-tools ebtables kubectl kubernetes-cni socat
    kubearmor-dev-next: Suggested packages:
    kubearmor-dev-next:   nftables
    kubearmor-dev-next: The following NEW packages will be installed:
    kubearmor-dev-next:   conntrack cri-tools ebtables kubeadm kubectl kubelet kubernetes-cni socat
    kubearmor-dev-next: 0 upgraded, 8 newly installed, 0 to remove and 0 not upgraded.
    kubearmor-dev-next: Need to get 70.6 MB of archives.
    kubearmor-dev-next: After this operation, 310 MB of additional disk space will be used.
    kubearmor-dev-next: Get:1 http://archive.ubuntu.com/ubuntu impish/main amd64 conntrack amd64 1:1.4.6-2build1 [33.5 kB]
    kubearmor-dev-next: Get:2 http://archive.ubuntu.com/ubuntu impish/main amd64 ebtables amd64 2.0.11-4build1 [85.4 kB]
    kubearmor-dev-next: Get:3 http://archive.ubuntu.com/ubuntu impish/main amd64 socat amd64 1.7.4.1-3ubuntu1 [341 kB]
    kubearmor-dev-next: Get:4 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 cri-tools amd64 1.13.0-01 [8775 kB]
    kubearmor-dev-next: Get:5 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubernetes-cni amd64 0.8.7-00 [25.0 MB]
    kubearmor-dev-next: Get:6 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubelet amd64 1.21.3-00 [18.8 MB]
    kubearmor-dev-next: Get:7 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubectl amd64 1.22.2-00 [9038 kB]
    kubearmor-dev-next: Get:8 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubeadm amd64 1.21.3-00 [8549 kB]
    kubearmor-dev-next: dpkg-preconfigure: unable to re-open stdin: No such file or directory
    kubearmor-dev-next: Fetched 70.6 MB in 53s (1324 kB/s)
    kubearmor-dev-next: Selecting previously unselected package conntrack.
    kubearmor-dev-next: (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 106671 files and directories currently installed.)
    kubearmor-dev-next: Preparing to unpack .../0-conntrack_1%3a1.4.6-2build1_amd64.deb ...
    kubearmor-dev-next: Unpacking conntrack (1:1.4.6-2build1) ...
    kubearmor-dev-next: Selecting previously unselected package cri-tools.
    kubearmor-dev-next: Preparing to unpack .../1-cri-tools_1.13.0-01_amd64.deb ...
    kubearmor-dev-next: Unpacking cri-tools (1.13.0-01) ...
    kubearmor-dev-next: Selecting previously unselected package ebtables.
    kubearmor-dev-next: Preparing to unpack .../2-ebtables_2.0.11-4build1_amd64.deb ...
    kubearmor-dev-next: Unpacking ebtables (2.0.11-4build1) ...
    kubearmor-dev-next: Selecting previously unselected package kubernetes-cni.
    kubearmor-dev-next: Preparing to unpack .../3-kubernetes-cni_0.8.7-00_amd64.deb ...
    kubearmor-dev-next: Unpacking kubernetes-cni (0.8.7-00) ...
    kubearmor-dev-next: Selecting previously unselected package socat.
    kubearmor-dev-next: Preparing to unpack .../4-socat_1.7.4.1-3ubuntu1_amd64.deb ...
    kubearmor-dev-next: Unpacking socat (1.7.4.1-3ubuntu1) ...
    kubearmor-dev-next: Selecting previously unselected package kubelet.
    kubearmor-dev-next: Preparing to unpack .../5-kubelet_1.21.3-00_amd64.deb ...
    kubearmor-dev-next: Unpacking kubelet (1.21.3-00) ...
    kubearmor-dev-next: Selecting previously unselected package kubectl.
    kubearmor-dev-next: Preparing to unpack .../6-kubectl_1.22.2-00_amd64.deb ...
    kubearmor-dev-next: Unpacking kubectl (1.22.2-00) ...
    kubearmor-dev-next: Selecting previously unselected package kubeadm.
    kubearmor-dev-next: Preparing to unpack .../7-kubeadm_1.21.3-00_amd64.deb ...
    kubearmor-dev-next: Unpacking kubeadm (1.21.3-00) ...
    kubearmor-dev-next: Setting up conntrack (1:1.4.6-2build1) ...
    kubearmor-dev-next: Setting up kubectl (1.22.2-00) ...
    kubearmor-dev-next: Setting up ebtables (2.0.11-4build1) ...
    kubearmor-dev-next: Setting up socat (1.7.4.1-3ubuntu1) ...
    kubearmor-dev-next: Setting up cri-tools (1.13.0-01) ...
    kubearmor-dev-next: Setting up kubernetes-cni (0.8.7-00) ...
    kubearmor-dev-next: Setting up kubelet (1.21.3-00) ...
    kubearmor-dev-next: Created symlink /etc/systemd/system/multi-user.target.wants/kubelet.service → /lib/systemd/system/kubelet.service.
    kubearmor-dev-next: Setting up kubeadm (1.21.3-00) ...
    kubearmor-dev-next: Processing triggers for man-db (2.9.4-2) ...
    kubearmor-dev-next: 
    kubearmor-dev-next: Running kernel seems to be up-to-date.
    kubearmor-dev-next: 
    kubearmor-dev-next: No services need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No containers need to be restarted.
    kubearmor-dev-next: 
    kubearmor-dev-next: No user sessions are running outdated binaries.
    kubearmor-dev-next: bpffs                                     /sys/fs/bpf     bpf     defaults          0       0
    kubearmor-dev-next: Reading package lists...
    kubearmor-dev-next: Building dependency tree...
    kubearmor-dev-next: Reading state information...
    kubearmor-dev-next: apparmor is already the newest version (3.0.3-0ubuntu1).
    kubearmor-dev-next: apparmor-utils is already the newest version (3.0.3-0ubuntu1).
    kubearmor-dev-next: auditd is already the newest version (1:3.0-2ubuntu2).
    kubearmor-dev-next: The following packages were automatically installed and are no longer required:
    kubearmor-dev-next:   accountsservice language-selector-common libaccountsservice0
    kubearmor-dev-next: Use 'sudo apt autoremove' to remove them.
    kubearmor-dev-next: 0 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.
    kubearmor-dev-next: Synchronizing state of auditd.service with SysV service script with /lib/systemd/systemd-sysv-install.
    kubearmor-dev-next: Executing: /lib/systemd/systemd-sysv-install enable auditd
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: /tmp/vagrant-shell20211020-109471-1rgi52y.sh
    kubearmor-dev-next: I1020 21:02:09.763613   17126 version.go:254] remote version is much newer: v1.22.2; falling back to: stable-1.21
    kubearmor-dev-next: [init] Using Kubernetes version: v1.21.5
    kubearmor-dev-next: [preflight] Running pre-flight checks
    kubearmor-dev-next: [preflight] Pulling images required for setting up a Kubernetes cluster
    kubearmor-dev-next: [preflight] This might take a minute or two, depending on the speed of your internet connection
    kubearmor-dev-next: [preflight] You can also perform this action in beforehand using 'kubeadm config images pull'
    kubearmor-dev-next: [certs] Using certificateDir folder "/etc/kubernetes/pki"
    kubearmor-dev-next: [certs] Generating "ca" certificate and key
    kubearmor-dev-next: [certs] Generating "apiserver" certificate and key
    kubearmor-dev-next: [certs] apiserver serving cert is signed for DNS names [kubearmor-dev-next kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local] and IPs [10.96.0.1 10.0.2.15]
    kubearmor-dev-next: [certs] Generating "apiserver-kubelet-client" certificate and key
    kubearmor-dev-next: [certs] Generating "front-proxy-ca" certificate and key
    kubearmor-dev-next: [certs] Generating "front-proxy-client" certificate and key
    kubearmor-dev-next: [certs] Generating "etcd/ca" certificate and key
    kubearmor-dev-next: [certs] Generating "etcd/server" certificate and key
    kubearmor-dev-next: [certs] etcd/server serving cert is signed for DNS names [kubearmor-dev-next localhost] and IPs [10.0.2.15 127.0.0.1 ::1]
    kubearmor-dev-next: [certs] Generating "etcd/peer" certificate and key
    kubearmor-dev-next: [certs] etcd/peer serving cert is signed for DNS names [kubearmor-dev-next localhost] and IPs [10.0.2.15 127.0.0.1 ::1]
    kubearmor-dev-next: [certs] Generating "etcd/healthcheck-client" certificate and key
    kubearmor-dev-next: [certs] Generating "apiserver-etcd-client" certificate and key
    kubearmor-dev-next: [certs] Generating "sa" key and public key
    kubearmor-dev-next: [kubeconfig] Using kubeconfig folder "/etc/kubernetes"
    kubearmor-dev-next: [kubeconfig] Writing "admin.conf" kubeconfig file
    kubearmor-dev-next: [kubeconfig] Writing "kubelet.conf" kubeconfig file
    kubearmor-dev-next: [kubeconfig] Writing "controller-manager.conf" kubeconfig file
    kubearmor-dev-next: [kubeconfig] Writing "scheduler.conf" kubeconfig file
    kubearmor-dev-next: [kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
    kubearmor-dev-next: [kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
    kubearmor-dev-next: [kubelet-start] Starting the kubelet
    kubearmor-dev-next: [control-plane] Using manifest folder "/etc/kubernetes/manifests"
    kubearmor-dev-next: [control-plane] Creating static Pod manifest for "kube-apiserver"
    kubearmor-dev-next: [control-plane] Creating static Pod manifest for "kube-controller-manager"
    kubearmor-dev-next: [control-plane] Creating static Pod manifest for "kube-scheduler"
    kubearmor-dev-next: [etcd] Creating static Pod manifest for local etcd in "/etc/kubernetes/manifests"
    kubearmor-dev-next: [wait-control-plane] Waiting for the kubelet to boot up the control plane as static Pods from directory "/etc/kubernetes/manifests". This can take up to 4m0s
    kubearmor-dev-next: [apiclient] All control plane components are healthy after 12.503951 seconds
    kubearmor-dev-next: [upload-config] Storing the configuration used in ConfigMap "kubeadm-config" in the "kube-system" Namespace
    kubearmor-dev-next: [kubelet] Creating a ConfigMap "kubelet-config-1.21" in namespace kube-system with the configuration for the kubelets in the cluster
    kubearmor-dev-next: [upload-certs] Skipping phase. Please see --upload-certs
    kubearmor-dev-next: [mark-control-plane] Marking the node kubearmor-dev-next as control-plane by adding the labels: [node-role.kubernetes.io/master(deprecated) node-role.kubernetes.io/control-plane node.kubernetes.io/exclude-from-external-load-balancers]
    kubearmor-dev-next: [mark-control-plane] Marking the node kubearmor-dev-next as control-plane by adding the taints [node-role.kubernetes.io/master:NoSchedule]
    kubearmor-dev-next: [bootstrap-token] Using token: 1juclp.osiaiqf8q9z6ivnb
    kubearmor-dev-next: [bootstrap-token] Configuring bootstrap tokens, cluster-info ConfigMap, RBAC Roles
    kubearmor-dev-next: [bootstrap-token] configured RBAC rules to allow Node Bootstrap tokens to get nodes
    kubearmor-dev-next: [bootstrap-token] configured RBAC rules to allow Node Bootstrap tokens to post CSRs in order for nodes to get long term certificate credentials
    kubearmor-dev-next: [bootstrap-token] configured RBAC rules to allow the csrapprover controller automatically approve CSRs from a Node Bootstrap Token
    kubearmor-dev-next: [bootstrap-token] configured RBAC rules to allow certificate rotation for all node client certificates in the cluster
    kubearmor-dev-next: [bootstrap-token] Creating the "cluster-info" ConfigMap in the "kube-public" namespace
    kubearmor-dev-next: [kubelet-finalize] Updating "/etc/kubernetes/kubelet.conf" to point to a rotatable kubelet client certificate and key
    kubearmor-dev-next: [addons] Applied essential addon: CoreDNS
    kubearmor-dev-next: [addons] Applied essential addon: kube-proxy
    kubearmor-dev-next: 
    kubearmor-dev-next: Your Kubernetes control-plane has initialized successfully!
    kubearmor-dev-next: 
    kubearmor-dev-next: To start using your cluster, you need to run the following as a regular user:
    kubearmor-dev-next: 
    kubearmor-dev-next:   mkdir -p $HOME/.kube
    kubearmor-dev-next:   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    kubearmor-dev-next:   sudo chown $(id -u):$(id -g) $HOME/.kube/config
    kubearmor-dev-next: 
    kubearmor-dev-next: Alternatively, if you are the root user, you can run:
    kubearmor-dev-next: 
    kubearmor-dev-next:   export KUBECONFIG=/etc/kubernetes/admin.conf
    kubearmor-dev-next: 
    kubearmor-dev-next: You should now deploy a pod network to the cluster.
    kubearmor-dev-next: Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
    kubearmor-dev-next:   https://kubernetes.io/docs/concepts/cluster-administration/addons/
    kubearmor-dev-next: 
    kubearmor-dev-next: Then you can join any number of worker nodes by running the following on each as root:
    kubearmor-dev-next: 
    kubearmor-dev-next: kubeadm join 10.0.2.15:6443 --token 1juclp.osiaiqf8q9z6ivnb \
    kubearmor-dev-next: 	--discovery-token-ca-cert-hash sha256:98afa573307715f95bc3dd8b45fae027db9705e47fc33ae25863182692b03b80
    kubearmor-dev-next: export KUBECONFIG=/home/vagrant/.kube/config
    kubearmor-dev-next: serviceaccount/cilium created
    kubearmor-dev-next: serviceaccount/cilium-operator created
    kubearmor-dev-next: configmap/cilium-config created
    kubearmor-dev-next: clusterrole.rbac.authorization.k8s.io/cilium created
    kubearmor-dev-next: clusterrole.rbac.authorization.k8s.io/cilium-operator created
    kubearmor-dev-next: clusterrolebinding.rbac.authorization.k8s.io/cilium created
    kubearmor-dev-next: clusterrolebinding.rbac.authorization.k8s.io/cilium-operator created
    kubearmor-dev-next: daemonset.apps/cilium created
    kubearmor-dev-next: deployment.apps/cilium-operator created
    kubearmor-dev-next: node/kubearmor-dev-next untainted
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: inline script
==> kubearmor-dev-next: Running provisioner: shell...
    kubearmor-dev-next: Running: /tmp/vagrant-shell20211020-109471-1i4x29x.sh
