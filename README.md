# PDFId Service

This Assemblyline service extracts metadata and objects from PDF files
using Didier Stevens PDFId (Version 2.4) and PDFParser (Version 6.8)
tools.

**NOTE**: This service does not require you to buy any licence and is
preinstalled and working after a default installation

## Configuration

To add keywords to PDFId's search list, edit the following configuration
parameter:

ADDITIONAL_KEYS=(Default: \["/URI"])

To add new plugin scripts to PDFId, edit the following configuration parameter (must be under directory /opt/al/pkg/):

HEURISTICS=(Default: \[

"al_services/alsvc_pdfid/pdfid/plugin_embeddedfile", 

"al_services/alsvc_pdfid/pdfid/plugin_nameobfuscation",

"al_services/alsvc_pdfid/pdfid/plugin_suspicious_properties", 

"al_services/alsvc_pdfid/pdfid/plugin_triage"

])

To change the maximum sample size (in bytes) that the service will process, change this configuration parameter:
'MAX_PDF_SIZE'=(Default 3000000) *Note:* deep scan mode will ignore this configuration parameter. 

## Execution

The PDFId service will report the following information for each file when present:

### File Information


#### PDFId

- PDF Header String
- Number of:
    - objects
    - streams
    - endstreams
    - xref
    - trailer
    - startxref
    - '/Page'
    - '/Encrypt'
    - '/Objstm'
    - '/JS'
    - '/Javascript'
    - '/AA'
    - '/OpenAction'
    - '/AcroForm'
    - '/JBIG2Decode'
    - '/RichMedia'
    - '/Launch'
    - '/Colours'
    - '%%EOF'
    - Bytes after %%EOF
- Total entropy
- Entropy inside streams
- Entropy outside streams
- Mod Date (AL tag: PDF_DATE_MOD)
- Creation Date (AL tag: PDF_DATE_CREATION)
- Last Modification Date (AL tag: PDF_DATE_LASTMODIFIED)
- Source Modified Date (AL tag: PDF_DATE_SOURCEMODIFIED)

#### PDFParser

*Note:* PDFParser will only run on a sample if in deep scan mode, or if PDFId plugins (see below) detected 
suspicious elements are present in the sample.

- Reports number of:
    - /Comment
    - /XREF
    - /Trailer
    - /StartXref
    - /Indirect object
    - /Catalog
    - /ExtGState
    - /Font
    - /FontDescriptor
    - /Pages

- Extracts PDF Elements:
    - Comments
    - Trailer
    - StartXref

- Extracts Suspicious Elements:
    - Entire Objects (as extracted file) when flagged by PDFId plugins
    (JBIG2Decode objects will only be extracted in deep scan mode).
    - Specific Object content (in AL result) and will run FrankenStrings
    Patterns against content to search for IOCs (determined by PDFId
    plugins).

- ObjStms
    - Service will attempt to reprocess object streams in samples as PDF
    files to re-run against PDFId and PDFParser analyzers. If in deep scan mode, a maximum of 100
    objstms will be reprocessed, otherwise a maximum of two will be reprocessed.

### PDFId Plugins

PDFId plugins are python scripts used by PDFId service to score
suspicious properties based on PDFId results. Plugins can be added to
service by users (see configuration above). The following format is
required for plugin scripts to work with this AL service:


    class cPDFiD[NAME](cPluginParent):
        onlyValidPDF = True
        name = '[NAME OF PLUGIN]'

        def __init__(self, oPDFiD):
            self.oPDFiD = oPDFiD
            # Whether or not hits is used, it must be returned by Score
            self.hits = []

        def Score(self):
            score = 0
            [conditions that might adjust score/self.hits]

            return score, self.hits

        def Instructions(self, score, hits):
            if score == 1000:
                # These messages will show in AL result,
                along with score
                return 'Some message'

            if score == 500:
                return 'Some other message'

            if score == 0:
                return

See source code under "pdfid" folder for examples of plugins already used by this service.



