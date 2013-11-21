# -*- coding: utf-8 -*-
import os
import sys

#from setuptools import setup, find_packages
from distutils.core import setup
from distutils.sysconfig import get_python_lib

overlay_warning = False
if "install" in sys.argv:
    lib_paths = [get_python_lib()]
    if lib_paths[0].startswith("/usr/lib/"):
        # We have to try also with an explicit prefix of /usr/local in order to
        # catch Debian's custom user site-packages directory.
        lib_paths.append(get_python_lib(prefix="/usr/local"))
        for lib_path in lib_paths:
            existing_path = os.path.abspath(os.path.join(lib_path, "led"))
            if os.path.exists(existing_path):
                # We note the need for the warning here, but present it after the
                # command is run, so it's more likely to be seen.
                overlay_warning = True
                break


#def _read(fname):
#    return open(os.path.join(os.path.dirname(__file__+'/src/led/'), fname)).read()


setup(
    name='led',
    version='0.1',
    description='Lazy Exploit Developers tool',
    package_dir={'led':'src'},
    packages=['led', 
        'led.utils', 
        'led.payloads',
        'led.shellcodes'
        ],
    #packages=find_packages(exclude=['test', 'TODO', 'tools']),
    #package_data={'led': ["config/*"]},
    #install_requires=_read('requirements.txt').split('\n'),
    #long_description=_read('README'),
    classifiers=[],
    keywords='exploiting',
    author='Internet Security Auditors',
    author_email='newlog@overflowedminds.net',
    url='https://github.com/newlog/exploiting/tree/master/led',
    license='WTFPLv2',
)

if overlay_warning:
    sys.stderr.write("""
        
        ============
        ADVERTENCIA!
        ============

        Has instalado Global API sobre una instalación existente, sin
        previamente eliminarla. Debido a esto, su instalación ahora puede
        incluir archivos extraños de una versión anterior que en la version
        actual de Global API han sido eliminados. Esto podría causar varios
        problemas. Debe eliminar manualmente el directorio y volver a
        instalar Global API.

        %(existing_path)s

    
        """ % {"existing_path": existing_path})

