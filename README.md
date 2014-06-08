#Install Linux on a Live Windows System

This is a fork of the InstallLinux program which I have only found here:
[Script Junkie][1]

>As you may know, I run the Red Team for the Collegiate Cyber Defense Competition (CCDC) in the southwest region. One of the more interesting things I put together for the regional competitions this year was a way to install Linux remotely over a command-line interface (such as meterpreter). I actually originally wrote it for a hypervisor rootkit, but it can be used for a simple Linux install as well.

>It works by using windows diskpart commands to create a new primary partition, (shrinking an existing partition as necessary) setting it to be bootable, then writing out a compressed linux install into that partition, and installing the syslinux bootloader into the MBR. It can keep a backup of the original MBR in the new partition as well. For SWCCDC, I used a small image from a TinyCore install I modified with a little red team branding.

>It leaves the original partitions intact, so if you wanted to use a Linux partition image with GRUB installed, it?s entirely possible to make a multiboot Linux install via this method, or recover easily if you accidentally do it to yourself.

[Demo Video][2]


  [1]: http://www.scriptjunkie.us/2014/02/installing-linux-on-a-live-windows-system/
  [2]: https://www.youtube.com/watch?v=TrnUO6TLrtE