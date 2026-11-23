# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax.expatreader
"""
from __future__ import print_function, absolute_import

from xml.sax.expatreader import ExpatParser as _ExpatParser

from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden

__origin__ = "xml.sax.expatreader"


class DefusedExpatParser(_ExpatParser):
    """Defused SAX driver for the pyexpat C module."""

    def __init__(
        self,
        namespaceHandling=0,
        bufsize=2**16 - 20,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        super().__init__(namespaceHandling, bufsize)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        if not self.forbid_dtd:
            if self._lex_handler_prop is None:
                # The stdlib only installs StartDoctypeDeclHandler when a
                # lexical handler is present, see
                # ExpatParser._reset_lex_handler_prop().
                return
            return _ExpatParser.start_doctype_decl(self, name, sysid, pubid, has_internal_subset)
        raise DTDForbidden(name, sysid, pubid)

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        if not self.forbid_entities:
            return
        raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        if not self.forbid_entities:
            if self._dtd_handler is None:
                # The stdlib only installs UnparsedEntityDeclHandler when a
                # DTD handler is present, see ExpatParser.reset().
                return
            return _ExpatParser.unparsed_entity_decl(
                self, name, base, sysid, pubid, notation_name
            )
        raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)  # pragma: no cover

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        if not self.forbid_external:
            return _ExpatParser.external_entity_ref(self, context, base, sysid, pubid)
        raise ExternalReferenceForbidden(context, base, sysid, pubid)

    def reset(self):
        super().reset()
        parser = self._parser
        # The handlers are installed unconditionally and consult the
        # mutable forbid_* attributes on every callback. The parent
        # reset() runs on every parse and rebinds the stdlib handlers, so
        # they are overwritten here each time while policy changes remain
        # effective without another reset.
        parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        parser.EntityDeclHandler = self.defused_entity_decl
        parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler


def create_parser(*args, **kwargs):
    return DefusedExpatParser(*args, **kwargs)
