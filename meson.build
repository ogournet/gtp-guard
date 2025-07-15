# SPDX-License-Identifier: AGPL-3.0-or-later

project('gtp-guard', 'c',
	version : files('VERSION'),
	meson_version: '>= 0.59.0',
	license: 'AGPL-3.0-or-later',
	default_options : [
	  'buildtype=debug',
	  'werror=false',
	  'warning_level=2',
	  'c_std=gnu99'
	]
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-Wstrict-prototypes', language: 'c')
add_project_arguments('-Wno-extra', language: 'c')
add_project_arguments('-ggdb', language: 'c')

# get programs to compile ebpf
clang = find_program('clang', required : true)
llc = find_program('llc', required : true)
arch = 'x86'

# libraries this project is using
libcrypt_dep = dependency('libcrypt')
libelf_dep = dependency('libelf')

# XXX should compile libbpf as a subproject
# for now, use system package libbpf.
libbpf_dep = dependency('libbpf', version : '>=1.5.0')
libbpf_inc = libbpf_dep.get_variable('includedir') + '/bpf'

src = []
inc = [ libbpf_inc ]

subdir('lib')
subdir('src')
subdir('tools/selftests')

executable(
  'gtp-guard', src,
  include_directories: inc,
  dependencies: [libbpf_dep, libcrypt_dep, libelf_dep],
  link_args : [ '-lresolv' ],
  install: true,
)
