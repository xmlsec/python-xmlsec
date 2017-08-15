import os
import sys

try:
    from urlparse import urljoin
    from urllib import urlretrieve, urlcleanup
except ImportError:
    from urllib.parse import urljoin
    from urllib.request import urlretrieve, urlcleanup


# use pre-built libraries on Windows
def get_prebuilt_libs(download_dir, static_include_dirs, static_library_dirs):
    assert sys.platform.startswith('win')
    libs = download_and_extract_windows_binaries(download_dir)
    for ln, path in libs.items():
        if ln == 'xmlsec1':
            i = os.path.join(path, 'include', 'xmlsec1')
        else:
            i = os.path.join(path, 'include')

        l = os.path.join(path, 'lib')
        assert os.path.exists(i), 'does not exist: %s' % i
        assert os.path.exists(l), 'does not exist: %s' % l
        static_include_dirs.append(i)
        static_library_dirs.append(l)


def download_and_extract_windows_binaries(destdir):
    if sys.version_info < (3, 5):
        if sys.maxsize > 2147483647:
            url = "https://ci.appveyor.com/api/buildjobs/7q4nvmkdnu05dul6/artifacts/"
            suffix = "vs2008.win64"
        else:
            url = "https://ci.appveyor.com/api/buildjobs/tdpx6rprr5431ec9/artifacts/"
            suffix = "vs2008.win32"
    else:
        if sys.maxsize > 2147483647:
            url = "https://ci.appveyor.com/api/buildjobs/hij3a6776pdv2007/artifacts/"
            suffix = "win64"
        else:
            url = "https://ci.appveyor.com/api/buildjobs/7k878q7rvogcdyd9/artifacts/"
            suffix = "win32"

    libs = {
        'libxml2': 'libxml2-2.9.4.{}.zip'.format(suffix),
        'libxslt': 'libxslt-1.1.29.{}.zip'.format(suffix),
        'zlib': 'zlib-1.2.8.{}.zip'.format(suffix),
        'iconv': 'iconv-1.14.{}.zip'.format(suffix),
        'openssl': 'openssl-1.0.1.{}.zip'.format(suffix),
        'xmlsec': 'xmlsec-1.2.24.{}.zip'.format(suffix),
    }

    if not os.path.exists(destdir):
        os.makedirs(destdir)

    for ln, fn in libs.items():
        srcfile = urljoin(url, fn)
        destfile = os.path.join(destdir, fn)
        if os.path.exists(destfile + ".keep"):
            print('Using local copy of  "{}"'.format(srcfile))
        else:
            print('Retrieving "%s" to "%s"' % (srcfile, destfile))
            urlcleanup()  # work around FTP bug 27973 in Py2.7.12+
            urlretrieve(srcfile, destfile)

        libs[ln] = unpack_zipfile(destfile, destdir)

    return libs


def find_top_dir_of_zipfile(zipfile):
    topdir = None
    files = [f.filename for f in zipfile.filelist]
    dirs = [d for d in files if d.endswith('/')]
    if dirs:
        dirs.sort(key=len)
        topdir = dirs[0]
        topdir = topdir[:topdir.index("/")+1]
        for path in files:
            if not path.startswith(topdir):
                topdir = None
                break
    assert topdir, (
        "cannot determine single top-level directory in zip file %s" %
        zipfile.filename)
    return topdir.rstrip('/')


def unpack_zipfile(zipfn, destdir):
    assert zipfn.endswith('.zip')
    import zipfile
    print('Unpacking %s into %s' % (os.path.basename(zipfn), destdir))
    f = zipfile.ZipFile(zipfn)
    try:
        extracted_dir = os.path.join(destdir, find_top_dir_of_zipfile(f))
        f.extractall(path=destdir)
    finally:
        f.close()
    assert os.path.exists(extracted_dir), 'missing: %s' % extracted_dir
    return extracted_dir
