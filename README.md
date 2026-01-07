# Install packages
opkg update
opkg install parted losetup resize2fs blkid
 
# Download expand-root.sh
wget -U "" -O expand-root.sh "https://openwrt.org/_export/code/docs/guide-user/advanced/expand_root?codeblock=0"
 
# Source the script (creates /etc/uci-defaults/70-rootpt-resize and /etc/uci-defaults/80-rootpt-resize, and adds them to /etc/sysupgrade.conf so they will be re-run after a sysupgrade)
. ./expand-root.sh
 
调整根分区和文件系统的大小（将调整分区大小，重新启动调整文件系统大小，然后再次重新启动）

sh /etc/uci-defaults/70-rootpt-resize

重新运行脚本

如果根分区已被扩展，并且之前已运行过expand-root.sh脚本，则默认情况下尝试再次运行它不起作用。要执行额外的根扩展，您需要删除之前的脚本标志：

rm /etc/rootpt-resize rm /etc/rootfs-resize

打开/etc/sysupgrade.conf文件，并删除以下行：

/etc/uci-defaults/70-rootpt-resize 
/etc/uci-defaults/80-rootfs-resize

这确保了系统不再认为脚本已执行，然后您可以重新运行脚本。
