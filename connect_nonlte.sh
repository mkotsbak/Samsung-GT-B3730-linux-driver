#!/bin/sh

# This requires that "kalmia.ko" and updated "option.ko" placed under /lib/modules...
# and "depmod" run (check with "modinfo kalmia")

sudo ifdown wwan0
chat -vs -f chatscript_nonlte.txt < /dev/ttyUSB0 > /dev/ttyUSB0
sudo ifup wwan0
minicom -o -D /dev/ttyUSB0
