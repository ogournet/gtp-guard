# SPDX-License-Identifier: AGPL-3.0-or-later

test_src = files(
  '../../../src/gtp_resolv.c',
  '../../../src/gtp_sched.c',
  '../../../src/gtp_interface.c',
  '../../../src/gtp_bpf_prog.c',
  '../../../src/gtp_bpf.c',
)

executable(
  'test-resolv',
  files('main.c') + lib_src + test_src,
  include_directories: inc,
  dependencies: [libbpf_dep, libcrypt_dep, libelf_dep],
  link_args : [ '-lresolv' ],
  install: false,
)
