import html.parser
import os
import re
from distutils import log
from distutils.version import StrictVersion as Version

from .network import make_request


class HrefCollector(html.parser.HTMLParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for name, value in attrs:
                if name == 'href':
                    self.hrefs.append(value)


def latest_release_from_html(url, matcher):
    content = make_request(url)
    collector = HrefCollector()
    collector.feed(content)
    hrefs = collector.hrefs

    def comp(text):
        try:
            return Version(matcher.match(text).groupdict()['version'])
        except (AttributeError, ValueError):
            return Version('0.0')

    latest = max(hrefs, key=comp)
    return f'{url}/{latest}'


def latest_release_from_gnome_org_cache(url, lib_name):
    cache_url = f'{url}/cache.json'
    cache = make_request(cache_url, json_response=True)
    latest_version = cache[2][lib_name][-1]
    latest_source = cache[1][lib_name][latest_version]['tar.xz']
    return f'{url}/{latest_source}'


def latest_release_json_from_github_api(repo):
    api_url = f'https://api.github.com/repos/{repo}/releases/latest'
    token = os.environ.get('GH_TOKEN')
    if token:
        log.info('Using GitHub token to avoid rate limiting')
    return make_request(api_url, token, json_response=True)


def latest_openssl_release():
    return latest_release_json_from_github_api('openssl/openssl')['tarball_url']


def latest_zlib_release():
    return latest_release_from_html('https://zlib.net/fossils', re.compile('zlib-(?P<version>.*).tar.gz'))


def latest_libiconv_release():
    return latest_release_from_html('https://ftpmirror.gnu.org/libiconv', re.compile('libiconv-(?P<version>.*).tar.gz'))


def latest_libxml2_release():
    return latest_release_from_gnome_org_cache('https://download.gnome.org/sources/libxml2', 'libxml2')


def latest_libxslt_release():
    return latest_release_from_gnome_org_cache('https://download.gnome.org/sources/libxslt', 'libxslt')


def latest_xmlsec_release():
    assets = latest_release_json_from_github_api('lsh123/xmlsec')['assets']
    (tar_gz,) = [asset for asset in assets if asset['name'].endswith('.tar.gz')]
    return tar_gz['browser_download_url']
