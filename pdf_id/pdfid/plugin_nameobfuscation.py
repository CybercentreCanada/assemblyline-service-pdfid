#!/usr/bin/env python

#2013/11/04
#2013/11/08

class cPDFiDNameObfuscation(cPluginParent):
#    onlyValidPDF = True
    name = 'Name Obfuscation plugin'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD
        self.hits = []

    def Score(self):
        if sum([oCount.hexcode for oCount in self.oPDFiD.keywords.values()]) > 0:
            return 18, self.hits
        else:
            return 0, self.hits

    def Instructions(self, score, hits):
        if score == 0:
            return "No hex encoded flags detected."
        if score == 18:
            return 'Hex encoded flag(s) detected.'

AddPlugin(cPDFiDNameObfuscation)
