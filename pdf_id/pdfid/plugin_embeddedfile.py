#!/usr/bin/env python

#2014/10/13

class cPDFiDEmbeddedFile(cPluginParent):
#    onlyValidPDF = True
    name = 'EmbeddedFile plugin'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD
        self.hits = []

    def Score(self):
        if '/EmbeddedFile' in self.oPDFiD.keywords and self.oPDFiD.keywords['/EmbeddedFile'].count > 0:
                if self.oPDFiD.keywords['/EmbeddedFile'].hexcode > 0:
                    return 16, self.hits
                else:
                    return 15, self.hits
        return 0, self.hits

    def Instructions(self, score, hits):
        if score == 16:
            return 'EmbeddedFile flag(s) are hex encoded. Sample is likely malicious.'

        if score == 15:
            return 'EmbeddedFile flag(s) detected. Sample requires further analysis.'

        if score == 0:
            return

AddPlugin(cPDFiDEmbeddedFile)
