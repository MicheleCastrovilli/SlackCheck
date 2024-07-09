# SlackCheck
## Kernel Module version

### Compiling the Module

Compiling the kernel is a long process, as it involves compiling the Linux Kernel.
To keep the filesystem tidy, I will refer to the build folder as ``~/Build``, feel
free to use any other folder or name, changing it in the following steps. Make sure
to have all the necessary tools to compile the kernel.

Steps from a Terminal:

* ``cd ~/Build``
* ``git clone --depth 1 --branch v6.7 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git``
* Put the ``0001-SlackCheck.patch`` in the newly made ``linux`` folder.
* ``git apply 0001-SlackCheck.patch``
* Copy the current kernel configuration into the ``linux`` folder as a ``.config`` file. 

  * In Arch/Gentoo, this config can be extracted with the ``zcat`` program.
    This means, ``zcat /proc/config.gz > ~/Build/linux/.config``. 
  * In Ubuntu/Debian, the config should be in the ``/boot`` folder, so the following
    command should get it most of the way there. ``cp /boot/config-$(uname -r) ~/Build/linux/.config``.

* ``cd ~/Build/linux``
* ``make menuconfig``

  * Load first the ``.config`` file.
  * > Kernel Hacking (then enter)
  * > Select "Tracers" with Space (to make sure the [\*] is present), then Enter
  * > Select "Runtime Verification" (Space, then Enter)
  * > Select "timed monitor" (Space)
  * Save, Enter
  * Exit (multiple times for each menu)

* ``make -j<number of cores to use>`` (This will take a long time)
* ``sudo make headers_install``
* ``sudo make modules_install``
* Depending on the Distribution used, the following steps might be different. For completeness
  here are some distribution guides on how to install the last step.

  * Arch: https://wiki.archlinux.org/title/Kernel/Traditional_compilation#Copy_the_kernel_to_/boot_directory
  * Ubuntu: https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel
  * Debian: https://debian-handbook.info/browse/stable/sect.kernel-compilation.html

Once this last step is done, rebooting should allow the bootloader to select the new kernel.

### Running SlackCheck

Once SlackCheck is compiled and the kernel is running, the interface to interact
with the module is simple. Root access is needed to modify the files exposed
by the module. 

Enabling/Disabling the monitor:

* Enable: ``echo 1 | sudo tee /sys/kernel/debug/tracing/rv/monitors/timed/enable``
* Disable: ``echo 0 | sudo tee /sys/kernel/debug/tracing/rv/monitors/timed/enable``

Setting various parameters: 

* Filename of the monitored process: ``echo "<name>" | sudo tee /proc/rv_timed_proc_filename``.
  This will allow the monitor to check for a newly started process with the specified file path.
  That is, the fully qualified path to get to the executable. As soon as a ``sched_process_exec``
  event with a process of specified filename happens, the monitor will set this as the ``out_0``
  value, and will start to monitor the process.
* PID of the monitored process: ``echo PID | sudo tee /proc/rv_timed_proc_pid``. Same as
  the filename version, but it will also listen to ``sched_switch`` events, since the process has already
  begun.
* Unused in the current version: ``echo <1 or 0> | sudo tee /proc/rv_timed_check_all``.
  It would toggle whether the negative slack condition is checked at every scheduling event,
  even of unrelated task, in order to improve the response time of the module.
* Latency: ``echo <latency in ns> | sudo tee /proc/rv_timed_latency_ns``. This setting indicates the
  delta parameter in nanoseconds, as the maximum latency acceptable for a process to respond.
* Utilization rate:

  * Numerator: ``echo <n> | sudo tee /proc/rv_timed_rate_num``
  * Denominator: ``echo <n> | sudo tee /proc/rv_timed_rate_den``
  * It is important to note that the program always makes sure that both the
    numerator or denominator cannot be zero. Furthermore, the denominator has
    to always be greater or equal than the numerator.
  * The program does not simplify the resulting fraction automatically, this has
    a repercussion in the slack precision, as higher values of the numerator will
    lead to a bigger remainder being "thrown away".

Once the monitor is running, it will print the slack value to the ``dmesg`` program.
This first version of SlackCheck uses the kernel message buffer to deliver the slack
value. It is a consideration to move this value delivery to a specific FIFO file instead,
in further versions.

By setting the various values, and enabling the monitor, this should allow an user
to use SlackCheck to monitor the slack of any task in the system. 
The current system is limited by a single task, but a further version of the work
will be able to handle more tasks at once.
