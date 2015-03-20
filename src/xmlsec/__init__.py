# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division
import atexit
from .meta import version as __version__, description as __doc__
from .constants import *
from .utils import *
from .key import *
from .ds import *
from .enc import *
from .error import *
from . import tree, template


if not init():
    raise RuntimeError('Failed to initialize the xmlsec library.')


atexit.register(shutdown)
