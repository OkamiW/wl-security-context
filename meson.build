project(
	'wl-security-context',
	'c',
	meson_version: '>=0.59.0',
	default_options: ['c_std=c11', 'warning_level=3', 'werror=true'],
)

cc = meson.get_compiler('c')

add_project_arguments(cc.get_supported_arguments([
	'-Wundef',
	'-Wlogical-op',
	'-Wmissing-include-dirs',
	'-Wold-style-definition',
	'-Wpointer-arith',
	'-Winit-self',
	'-Wstrict-prototypes',
	'-Wimplicit-fallthrough=2',
	'-Wendif-labels',
	'-Wstrict-aliasing=2',
	'-Woverflow',
	'-Wmissing-prototypes',
	'-Walloca',

	'-Wno-unused-parameter',
]), language: 'c')

wayland_protos = dependency('wayland-protocols',
	version: '>=1.31',
	fallback: 'wayland-protocols',
	default_options: ['tests=false'],
)
wl_protocol_dir = wayland_protos.get_variable('pkgdatadir')

wayland_scanner_dep = dependency('wayland-scanner', native: true)
wayland_scanner = find_program(
	wayland_scanner_dep.get_variable('wayland_scanner'),
	native: true,
)

protocols = {
	'security-context': wl_protocol_dir / 'staging/security-context/security-context-v1.xml',
}

protocols_code = {}
protocols_client_header = {}
foreach name, path : protocols
	code = custom_target(
		name.underscorify() + '_c',
		input: path,
		output: '@BASENAME@-protocol.c',
		command: [wayland_scanner, 'private-code', '@INPUT@', '@OUTPUT@'],
	)

	client_header = custom_target(
		name.underscorify() + '_client_h',
		input: path,
		output: '@BASENAME@-protocol.h',
		command: [wayland_scanner, 'client-header', '@INPUT@', '@OUTPUT@'],
		build_by_default: false,
	)

	protocols_code += { name: code }
	protocols_client_header += { name: client_header }
endforeach

src = ['wl-security-context.c']
extra_src = []
proto = ['security-context']

foreach p : proto
	extra_src += protocols_code[p]
	extra_src += protocols_client_header[p]
endforeach

wayland_client = dependency('wayland-client')

executable('wl-security-context', [src, extra_src], dependencies: [wayland_client], install: true)
