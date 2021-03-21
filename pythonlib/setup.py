#!/usr/bin/env python

"""
setup.py file for SWIG argusWgan
"""

from distutils.core import setup, Extension
import numpy as np

argusWgan = Extension('_argusWgan',
       extra_compile_args = ['-Wno-deprecated-declarations'], 
       sources=['argusWgan_wrap.c', 'argusWgan.c'],
       include_dirs=['../include', '/usr/local/include', np.get_include()],
       libraries=['m','GeoIP','z','curl'],
       extra_link_args=['../lib/argus_common.a','../lib/argus_client.a','../lib/argus_parse.a','/usr/local/lib/libtensorflow.dylib'],
    )

setup (name = 'argusWgan',
       version = '0.2',
       author  = 'Carter Bullard',
       author_email='carter@qosient.com',
       description = 'Time functions from argus client library',
       ext_modules = [argusWgan, Extension('_argusWgan', ['argusWgan.c'])],
       py_modules = ["argusWgan"],
    )
