#!/bin/bash

# cannot put symlink in packagefile because it doesn't work on meson < 1.7.0
# we do not want to expose -I headers, because headers/linux is a bit old.
# we only need headers/xdp.
ln -sf headers/xdp xdp

sed -e 's/[:() ]//g; q' version.mk > version_env
source version_env
echo $TOOLS_VERSION
