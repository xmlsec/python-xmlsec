# -*- coding: utf-8 -*-

__all__ = ["Error", "VerificationError", "InternalError"]


class Error(Exception):
    pass


class InternalError(Error):
    pass


class VerificationError(Error):
    pass
