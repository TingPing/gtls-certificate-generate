project('devs-tls-certificate', 'c')

executable('tls-certificate-gen',
  'devs-tls-certificate.c',
  'main.c',
  dependencies: [
    dependency('gio-2.0'),
    dependency('openssl')
  ]
)