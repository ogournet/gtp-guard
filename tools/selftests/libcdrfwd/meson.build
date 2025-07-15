# SPDX-License-Identifier: AGPL-3.0-or-later

test_src = files(
  '../../../src/carrier-grade-nat/cdr_fwd.c',
  '../../../src/carrier-grade-nat/cdr_fwd_adj.c',
  '../../../src/carrier-grade-nat/cdr_fwd_disk.c',
  '../../../src/carrier-grade-nat/cdr_fwd_spool.c',
  '../../../src/carrier-grade-nat/tools.c',
)

executable(
  'cdrfwd_test',
  files('cdr_test.c') + lib_src + test_src,
  include_directories: inc,
  dependencies: [libcrypt_dep],
  install: false,
)
