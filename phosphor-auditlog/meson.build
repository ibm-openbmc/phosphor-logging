auditd_dep = dependency('audit')
auparse_dep = dependency('auparse', required: true)

auditlog_sources = [
        files(
        'main.cpp',
        'alog_manager.cpp',
        'alog_parser.cpp',
        )
]

extra_args = []

# Add for in-depth debug, too much for normal use
# extra_args += ['-DAUDITLOG_FULL_DEBUG',]

# Add to keep JSON file around on exit of method
# extra_args += ['-DAUDITLOG_KEEP_JSONFILE',]

executable('phosphor-auditlog',
    auditlog_sources,
    include_directories: include_directories('..'),
    cpp_args: extra_args,
    dependencies: [
        conf_h_dep,
        phosphor_logging_dep,
        pdi_dep,
        sdbusplus_dep,
        sdeventplus_dep,
        auditd_dep,
        auparse_dep,
    ],
    install: true,
)
