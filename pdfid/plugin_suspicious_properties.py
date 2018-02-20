#!/usr/bin/env python

#2014/10/13

class cPDFiDSuspiciousProperties(cPluginParent):
#    onlyValidPDF = True
    name = 'Suspicious Properties plugin'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD
        self.hits = []

    def Score(self):
        score = 0
        # Entropy. Typically data outside of streams contain dictionaries & pdf entities (mostly all ASCII text).
        if self.oPDFiD.non_stream_entropy > 6:
            score += 500
            self.hits.append("entropy")
        # Pages. Many malicious PDFs will contain only one page.
        if '/Page' in self.oPDFiD.keywords and self.oPDFiD.keywords['/Page'].count == 1:
            score += 50
            self.hits.append("page")
        # Characters after last %%EOF.
        if self.oPDFiD.last_eof_bytes > 100:
            if self.oPDFiD.last_eof_bytes > 499:
                score += 500
                self.hits.append("eof5")
            else:
                score += 100
                self.hits.append("eof1")

        return score, self.hits

    def Instructions(self, score, hits):

        instruct = {
            'encrypt': 'Found the /Encrypt string in the file.\n',
            'entropy': 'Outside stream entropy of > 5 (Score 500).\n',
            'eof1': 'Over 100 characters after last %%EOF (Score 100).\n',
            'eof5': 'Over 500 characters after last %%EOF (Score 500).\n',
            'page': "Page count of 1 (Score 50)\n",
        }

        message = ""
        for h in hits:
            message += "{}" .format(instruct.get(h))

        if score > 0:
            return 'Suspicious properties identified in file:\n{}' .format(message)

        return

AddPlugin(cPDFiDSuspiciousProperties)
