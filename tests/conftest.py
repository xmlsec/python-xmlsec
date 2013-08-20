# -*- coding: utf-8 -*-
import sys
from os import path

# Get the base path.
base = path.join(path.dirname(__file__), '..')

# Append the source and test packages directories to PATH.
sys.path.append(path.join(base, 'src'))
