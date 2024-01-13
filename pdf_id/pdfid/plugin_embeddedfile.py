#!/usr/bin/env python
"""
Modified by CSE to fit ASSEMBLYLINE service
"""
from pdf_id.pdfid.pdfid import AddPlugin, cPluginParent

# 2014/10/13


class cPDFiDEmbeddedFile(cPluginParent):
    #    onlyValidPDF = True
    name = "EmbeddedFile plugin"

    def __init__(self, oPDFiD, options):
        self.oPDFiD = oPDFiD

    def Score(self):
        if "/EmbeddedFile" in self.oPDFiD.keywords and self.oPDFiD.keywords["/EmbeddedFile"].count > 0:
            if self.oPDFiD.keywords["/EmbeddedFile"].hexcode > 0:
                return 1.0
            else:
                return 0.9
        else:
            return 0.0


AddPlugin(cPDFiDEmbeddedFile)
