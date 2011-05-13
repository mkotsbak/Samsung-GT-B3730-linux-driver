#!/bin/sh

# This requires that "gt_b3730.ko" and updated "option.ko" placed under /lib/modules...
# and "depmod" run (check with "modinfo gt_b3730")

sudo ifdown wwan0
./chat.sh
sudo ifup wwan0
minicom -o -D /dev/ttyUSB0
