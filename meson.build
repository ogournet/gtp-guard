# SPDX-License-Identifier: AGPL-3.0-or-later

project('gtp-guard', 'c',
	version : files('VERSION'),
	meson_version: '>= 0.59.0',
	license: 'AGPL-3.0-or-later',
	default_options : [
	  'buildtype=debugoptimized',
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
clang = find_program('clang', required: true)
llc = find_program('llc', required: true)
arch = 'x86'

# libraries this project is using
libcrypt_dep = dependency('libcrypt')
libelf_dep = dependency('libelf')

# check for system's libbpf 
# if not found or version too old, fetch and compile libbpf from git
libbpf_dep = dependency('libbpf', version : '>=1.5.0', fallback: ['libbpf', 'libbpf_dep'])
libbpf_inc = libbpf_dep.get_variable('includedir') + '/bpf'

src = []
inc = []

subdir('lib')
subdir('src')

gtp_guard_exe = executable(
  'gtp-guard', src,
  c_args: [ '-I' + libbpf_inc ],
  include_directories: inc,
  dependencies: [libbpf_dep, libcrypt_dep, libelf_dep],
  link_args: [ '-lresolv' ],
  install: true,
)

subdir('tools/selftests')
