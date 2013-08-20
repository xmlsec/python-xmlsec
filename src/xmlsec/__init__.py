import atexit
from .meta import version as __version__, description as __doc__
from .constants import *
from .utils import *
from .key import *
from .ds import *
from . import tree


if not init():
    raise RuntimeError('Failed to initialize the xmlsec library.')


atexit.register(shutdown)
