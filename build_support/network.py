import contextlib
import json
from urllib.request import Request, urlopen

DEFAULT_USER_AGENT = 'https://github.com/xmlsec/python-xmlsec'
DOWNLOAD_USER_AGENT = 'python-xmlsec build'


def make_request(url, github_token=None, json_response=False):
    headers = {'User-Agent': DEFAULT_USER_AGENT}
    if github_token:
        headers['authorization'] = 'Bearer ' + github_token
    request = Request(url, headers=headers)
    with contextlib.closing(urlopen(request)) as response:
        charset = response.headers.get_content_charset() or 'utf-8'
        content = response.read().decode(charset)
        if json_response:
            return json.loads(content)
        return content


def download_lib(url, filename):
    request = Request(url, headers={'User-Agent': DOWNLOAD_USER_AGENT})
    with urlopen(request) as response, open(filename, 'wb') as target:
        while True:
            chunk = response.read(8192)
            if not chunk:
                break
            target.write(chunk)
