#! /usr/bin/env python
import sys
import subprocess
from os import path
from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext


#
# HACK
#

def getoutput(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    out, err = process.communicate()
    return out.decode('utf8')


def get_lxml_include_dirs():
  from os import environ
  lxml_home = environ.get("LXML_HOME")
  if lxml_home is None:
    # `LXML_HOME` not specified -- derive from installed `lxml`
    import lxml
    lxml_home = path.dirname(lxml.__file__)
  else:
    if not exists(lxml_home):
      sys.exit("The directory specified via envvar `LXML_HOME` does not exist")
    lxml_home = path.join(lxml_home, "src", "lxml")
  # check that it contains what is needed
  lxml_include = path.join(lxml_home, "includes")
  if not (path.exists(path.join(lxml_home, "etreepublic.pxd")) \
         or path.exists(path.join(lxml_include, "etreepublic.pxd"))):
    sys.exit("The lxml installation lacks the mandatory `etreepublic.pxd`. You may need to install `lxml` manually or set envvar `LXML_HOME` to an `lxml` installation with `etreepublic.pxd`")
  return [lxml_home, lxml_include]

# we must extend our cflags once `lxml` is installed.
#  To this end, we override `Extension`
class Extension(Extension, object):
  lxml_extended = False

  def get_include_dirs(self):
    ids = self.__dict__["include_dirs"]
    if self.lxml_extended: return ids
    # ensure `lxml` headers come before ours
    #  this should make sure to use its headers rather than our old copy
    # ids.extend(get_lxml_include_dirs())
    ids[0:0] = get_lxml_include_dirs()
    self.lxml_extended = True
    return ids

  def set_include_dirs(self, ids): self.__dict__["include_dirs"] = ids

  include_dirs = property(get_include_dirs, set_include_dirs)


define_macros = []
include_dirs  = ['src']
library_dirs  = []
libraries     = []

def extract_cflags(cflags):
    global define_macros, include_dirs
    list = cflags.split(' ')
    for flag in list:
        if flag == '':
            continue
        flag = flag.replace("\\\"", "")
        if flag[:2] == "-I":
            if flag[2:] not in include_dirs:
                include_dirs.append(flag[2:])
        elif flag[:2] == "-D":
            t = tuple(flag[2:].split('='))
            if len(t) == 1:
                t = (t[0], None)
            if t not in define_macros:
                define_macros.append(t)
        else:
            print("Warning : cflag %s skipped" % flag)

def extract_libs(libs):
    global library_dirs, libraries
    list = libs.split(' ')
    for flag in list:
        if flag == '':
            continue
        if flag[:2] == "-l":
            if flag[2:] not in libraries:
                libraries.append(flag[2:])
        elif flag[:2] == "-L":
            if flag[2:] not in library_dirs:
                library_dirs.append(flag[2:])
        else:
            print("Warning : linker flag %s skipped" % flag)


libxml2_cflags = getoutput('pkg-config libxml-2.0 --cflags')
if libxml2_cflags[:2] not in ["-I", "-D"]:
    libxml2_cflags = getoutput('xml2-config --cflags')
if libxml2_cflags[:2] not in ["-I", "-D"]:
    print("Error : cannot get LibXML2 pre-processor and compiler flags")

libxml2_libs = getoutput('pkg-config libxml-2.0 --libs')
if libxml2_libs[:2] not in ["-l", "-L"]:
    libxml2_libs = getoutput('xml2-config --libs')
if libxml2_libs[:2] not in ["-l", "-L"]:
    print("Error : cannot get LibXML2 linker flags")

xmlsec1_crypto = 'openssl'
cmd = 'pkg-config xmlsec1-%s --cflags' % xmlsec1_crypto
xmlsec1_cflags = getoutput(cmd)
if xmlsec1_cflags[:2] not in ["-I", "-D"]:
    cmd = 'xmlsec1-config --cflags --crypto=%s' % xmlsec1_crypto
    xmlsec1_cflags = getoutput(cmd)
if xmlsec1_cflags[:2] not in ["-I", "-D"]:
    print("Error : cannot get XMLSec1 pre-processor and compiler flags")

cmd = 'pkg-config xmlsec1-%s --libs' % xmlsec1_crypto
xmlsec1_libs = getoutput(cmd)
if xmlsec1_libs[:2] not in ["-l", "-L"]:
    cmd = 'xmlsec1-config --libs --crypto=%s' % xmlsec1_crypto
    xmlsec1_libs = getoutput(cmd)
if xmlsec1_libs[:2] not in ["-l", "-L"]:
    print("Error : cannot get XMLSec1 linker flags")

#print(libxml2_cflags)
#print libxml2_libs
#print xmlsec1_cflags
#print xmlsec1_libs

extract_cflags(libxml2_cflags)
extract_libs(libxml2_libs)

extract_cflags(xmlsec1_cflags)
extract_libs(xmlsec1_libs)

#
# END HACK
#

setup(
    name='xmlsec',
    version='0.1.0',
    description='Python bindings for the XML Security Library.',
    setup_requires=["lxml >= 3.0",],
    install_requires=[
        "lxml >= 3.0"
    ],
    cmdclass={'build_ext': build_ext},
    ext_modules=[
        Extension(
            'xmlsec', ['xmlsec.pyx'],
            define_macros=define_macros,
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries,
            depends=["src/" + f for f in "cxmlsec.pxd cxmlsec.h lxml.etree.h lxml-version.h lxml.etree_api.h".split()]
          )
    ],
)
