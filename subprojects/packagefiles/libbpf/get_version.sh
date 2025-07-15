#!/bin/bash

grep "^LIBBPF_.*VERSION" src/Makefile | grep -v shell > Makefile
cat<<EOF >> Makefile
all:
	@echo \$(LIBBPF_VERSION)
EOF
make -s
