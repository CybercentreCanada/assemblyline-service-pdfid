"""
Modified by CSE to fit ASSEMBLYLINE service
"""


class cPDFiDTriage(cPluginParent):
    onlyValidPDF = False
    name = 'Triage plugin'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD
        self.hits = set()

    def Score(self):
        """
        Modified by CSE to fit ASSEMBLYLINE Service
        """
        # Javascript - separated so we do not double-score
        if '/JS' in self.oPDFiD.keywords and self.oPDFiD.keywords['/JS'].count > 0:
            self.hits.add('/JS')
        if '/JavaScript' in self.oPDFiD.keywords and self.oPDFiD.keywords['/JavaScript'].count > 0:
            self.hits.add('/JavaScript')
        for keyword in ('/JBIG2Decode', '/Colors > 2^24'):
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                self.hits.add(keyword)
        # Auto open/Launch - separated so we do not double-score
        for keyword in ['/AA', '/GoToE', '/GoToR', '/OpenAction', '/Launch']:
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                self.hits.add(keyword)
        # Forms, Flash, XFA and Encrypted content
        for keyword in ['/AcroForm', '/Encrypt', '/RichMedia', '/XFA']:
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                self.hits.add(keyword)
        # Other content to flag for PDFParser to extract, but score low
        for keyword in ['/Annot', '/ObjStm', '/URI']:
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                self.hits.add(keyword)
        return 0, self.hits

    def Instructions(self, score, hits):
        """
        Modified by CSE to fit ASSEMBLYLINE Service
        Description information taken from https://blog.didierstevens.com/programs/pdf-tools/
        """
        instruct = {
            '/JS': '/JS: Javascript is present in the file.\n',
            '/JavaScript': '/JavaScript: Javascript is present in the file.\n',
            '/AA': '/AA: Automatic action to be performed when the page/document is viewed.\n',
            '/Annot': '/Annot: Contains annotations. '
                      'Not suspicious but should be examined if other signs of maliciousness present.\n',
            '/OpenAction': '/OpenAction: Automatic action to be performed when the page/document '
                           'is viewed."\n',
            '/AcroForm': '/AcroForm: Contains AcroForm object. These can be used to hide malicious code."\n',
            '/JBIG2Decode': '/JBIG2Decode: JBIG2 compression used."\n',
            '/RichMedia': '/RichMedia: Embedded Flash. \n',
            '/Launch': '/Launch: Counts launch actions.\n',
            '/Encrypt': '/Encrypt: Encrypted content in sample\n',
            '/XFA': '/XFA: XML Forms Architecture. These can be used to hide malicious code.\n',
            '/Colors > 2^24': '/Colors > 2^24: Number of colors is expressed with more than 3 bytes.\n',
            '/ObjStm': '/ObjStm: Contains object stream(s). Can be used to obfuscate objects.\n',
            '/URI': '/URI: Contains objects with URL(s).\n',
            '/GoToE': '/GoToE: Go to remote.\n',
            '/GoToR': '/GoToR: Go to embedded.\n'
        }

        message = "The following keywords have been flagged in this sample:\n"
        for h in hits:
            message += "{}".format(instruct.get(h))

        if len(hits) > 0:
            return message

        return

AddPlugin(cPDFiDTriage)
