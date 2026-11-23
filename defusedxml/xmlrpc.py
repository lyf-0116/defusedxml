# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xmlrpclib

Also defuses gzip bomb
"""
from __future__ import print_function, absolute_import

import io

from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden

__origin__ = "xmlrpc.client"
from xmlrpc.client import ExpatParser
from xmlrpc import client as xmlrpc_client
from xmlrpc import server as xmlrpc_server
from xmlrpc.client import gzip_decode as _orig_gzip_decode
from xmlrpc.client import GzipDecodedResponse as _OrigGzipDecodedResponse

try:
    import gzip
except ImportError:  # pragma: no cover
    gzip = None


# Limit maximum request size to prevent resource exhaustion DoS
# Also used to limit maximum amount of gzip decoded data in order to prevent
# decompression bombs
# A value of -1 or smaller disables the limit
MAX_DATA = 30 * 1024 * 1024  # 30 MB


def defused_gzip_decode(data, limit=None):
    """gzip encoded data -> unencoded data

    Decode data using the gzip content encoding as described in RFC 1952
    """
    if not gzip:  # pragma: no cover
        raise NotImplementedError
    if limit is None:
        limit = MAX_DATA
    f = io.BytesIO(data)
    gzf = gzip.GzipFile(mode="rb", fileobj=f)
    try:
        if limit < 0:  # no limit
            decoded = gzf.read()
        else:
            decoded = gzf.read(limit + 1)
    except IOError:  # pragma: no cover
        raise ValueError("invalid data")
    f.close()
    gzf.close()
    if limit >= 0 and len(decoded) > limit:
        raise ValueError("max gzipped payload length exceeded")
    return decoded


class DefusedGzipDecodedResponse(gzip.GzipFile if gzip else object):
    """a file-like object to decode a response encoded with the gzip
    method, as described in RFC 1952.
    """

    def __init__(self, response, limit=None):
        # response doesn't support tell() and read(), required by
        # GzipFile
        if not gzip:  # pragma: no cover
            raise NotImplementedError
        self.limit = limit = limit if limit is not None else MAX_DATA
        if limit < 0:  # no limit
            data = response.read()
            self.readlength = None
        else:
            data = response.read(limit + 1)
            self.readlength = 0
        if limit >= 0 and len(data) > limit:
            raise ValueError("max payload length exceeded")
        self.stringio = io.BytesIO(data)
        super().__init__(mode="rb", fileobj=self.stringio)

    def _check_limit(self, data):
        self.readlength += len(data)
        if self.readlength > self.limit:
            raise ValueError("max payload length exceeded")
        return data

    def _remaining(self):
        return max(self.limit - self.readlength, 0)

    def read(self, n=-1):
        if self.limit < 0:
            if n is None:
                n = -1
            return gzip.GzipFile.read(self, n)
        if n is None or n < 0:
            n = self._remaining() + 1
        else:
            n = min(n, self._remaining() + 1)
        return self._check_limit(gzip.GzipFile.read(self, n))

    def read1(self, n=-1):
        if self.limit < 0:
            if n is None:
                n = -1
            return gzip.GzipFile.read1(self, n)
        if n is None or n < 0:
            n = min(io.DEFAULT_BUFFER_SIZE, self._remaining() + 1)
        else:
            n = min(n, self._remaining() + 1)
        return self._check_limit(gzip.GzipFile.read1(self, n))

    def readline(self, size=-1):
        if self.limit < 0:
            if size is None:
                size = -1
            return gzip.GzipFile.readline(self, size)
        if size is None or size < 0:
            size = self._remaining() + 1
        else:
            size = min(size, self._remaining() + 1)
        return self._check_limit(gzip.GzipFile.readline(self, size))

    def readlines(self, hint=-1):
        if hint is None:
            hint = -1
        lines = []
        total = 0
        while True:
            line = self.readline()
            if not line:
                break
            lines.append(line)
            total += len(line)
            if hint > 0 and total >= hint:
                break
        return lines

    def peek(self, n=-1):
        if self.limit < 0:
            if n is None:
                n = -1
            return gzip.GzipFile.peek(self, n)
        if n is None or n < 0:
            n = self._remaining()
        else:
            n = min(n, self._remaining())
        if n <= 0:
            return b""
        return gzip.GzipFile.peek(self, n)[:n]

    def readinto(self, b):
        with memoryview(b) as view, view.cast("B") as byte_view:
            data = self.read(len(byte_view))
            byte_view[: len(data)] = data
        return len(data)

    def readinto1(self, b):
        with memoryview(b) as view, view.cast("B") as byte_view:
            data = self.read1(len(byte_view))
            byte_view[: len(data)] = data
        return len(data)

    def close(self):
        super().close()
        self.stringio.close()


class DefusedExpatParser(ExpatParser):
    def __init__(self, target, forbid_dtd=False, forbid_entities=True, forbid_external=True):
        super().__init__(target)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        parser = self._parser
        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.forbid_entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise DTDForbidden(name, sysid, pubid)

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)  # pragma: no cover

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        raise ExternalReferenceForbidden(context, base, sysid, pubid)


def monkey_patch():
    xmlrpc_client.FastParser = DefusedExpatParser
    xmlrpc_client.GzipDecodedResponse = DefusedGzipDecodedResponse
    xmlrpc_client.gzip_decode = defused_gzip_decode
    if xmlrpc_server:
        xmlrpc_server.gzip_decode = defused_gzip_decode


def unmonkey_patch():
    xmlrpc_client.FastParser = None
    xmlrpc_client.GzipDecodedResponse = _OrigGzipDecodedResponse
    xmlrpc_client.gzip_decode = _orig_gzip_decode
    if xmlrpc_server:
        xmlrpc_server.gzip_decode = _orig_gzip_decode
