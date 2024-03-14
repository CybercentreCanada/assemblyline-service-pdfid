"""
Modified by CSE to fit ASSEMBLYLINE service
"""


class cPDFiDSuspiciousProperties(cPluginParent):
    name = "Suspicious Properties plugin"

    def __init__(self, oPDFiD, options):
        self.oPDFiD = oPDFiD
        self.hits = set()

    def Score(self):
        # Entropy. Typically data outside of streams contain dictionaries & pdf entities (mostly all ASCII text).
        # if self.oPDFiD.non_stream_entropy > 6:
        #    self.hits.add("entropy")
        # Pages. Many malicious PDFs will contain only one page.
        if "/Page" in self.oPDFiD.keywords and self.oPDFiD.keywords["/Page"].count == 1:
            self.hits.add("page")
        # Characters after last %%EOF.
        # if self.oPDFiD.last_eof_bytes > 100:
        #    if self.oPDFiD.last_eof_bytes > 499:
        #        self.hits.add("eof5")
        #    else:
        #        self.hits.add("eof1")
        if self.oPDFiD.keywords["obj"].count != self.oPDFiD.keywords["endobj"].count:
            self.hits.add("obj/endobj")
        if self.oPDFiD.keywords["stream"].count != self.oPDFiD.keywords["endstream"].count:
            self.hits.add("stream/endstream")

        return 0.0, self.hits

    def Instructions(self, score_tuple):
        score, hits = score_tuple
        instruct = {
            "entropy": "Outside stream entropy of > 5.\n",
            "eof1": "Over 100 characters after last %%EOF.\n",
            "eof5": "Over 500 characters after last %%EOF.\n",
            "page": "Page count of 1\n",
            "obj/endobj": 'Sample "obj" keyword count does not equal "endobj" keyword count.\n',
            "stream/endstream": 'Sample "stream" keyword count does not equal "endstream" count.\n',
        }

        message = ""
        for h in hits:
            message += "{}".format(instruct.get(h))

        if len(hits) > 0:
            return "Suspicious properties identified in file:\n{}".format(message)

        return


AddPlugin(cPDFiDSuspiciousProperties)
