"""
Modified by CSE to fit ASSEMBLYLINE service
"""

__description__ = 'Tool to test a PDF file'
__author__ = 'Didier Stevens'
__version__ = '0.2.4'
__date__ = '2018/01/29'

"""

Tool to test a PDF file

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2009/03/27: start
  2009/03/28: scan option
  2009/03/29: V0.0.2: xml output
  2009/03/31: V0.0.3: /ObjStm suggested by Dion
  2009/04/02: V0.0.4: added ErrorMessage
  2009/04/20: V0.0.5: added Dates
  2009/04/21: V0.0.6: added entropy
  2009/04/22: added disarm
  2009/04/29: finished disarm
  2009/05/13: V0.0.7: added cPDFEOF
  2009/07/24: V0.0.8: added /AcroForm and /RichMedia, simplified %PDF header regex, extra date format (without TZ)
  2009/07/25: added input redirection, option --force
  2009/10/13: V0.0.9: added detection for CVE-2009-3459; added /RichMedia to disarm
  2010/01/11: V0.0.10: relaxed %PDF header checking
  2010/04/28: V0.0.11: added /Launch
  2010/09/21: V0.0.12: fixed cntCharsAfterLastEOF bug; fix by Russell Holloway
  2011/12/29: updated for Python 3, added keyword /EmbeddedFile
  2012/03/03: added PDFiD2JSON; coded by Brandon Dixon
  2013/02/10: V0.1.0: added http/https support; added support for ZIP file with password 'infected'
  2013/03/11: V0.1.1: fixes for Python 3
  2013/03/13: V0.1.2: Added error handling for files; added /XFA
  2013/11/01: V0.2.0: Added @file & plugins
  2013/11/02: continue
  2013/11/04: added options -c, -m, -v
  2013/11/06: added option -S
  2013/11/08: continue
  2013/11/09: added option -o
  2013/11/15: refactoring
  2014/09/30: added CSV header
  2014/10/16: V0.2.1: added output when plugin & file not pdf
  2014/10/18: some fixes for Python 3
  2015/08/12: V0.2.2: added option pluginoptions
  2015/08/13: added plugin Instructions method
  2016/04/12: added option literal
  2017/10/29: added pdfid.ini support
  2017/11/05: V0.2.3: added option -n
  2018/01/03: V0.2.4: bugfix entropy calculation for PDFs without streams; sample 28cb208d976466b295ee879d2d233c8a https://twitter.com/DubinRan/status/947783629123416069
  2018/01/15: bugfix ConfigParser privately reported
  2018/01/29: bugfix oPDFEOF.cntCharsAfterLastEOF when no %%EOF

Todo:
  - update XML example (entropy, EOF)
  - code review, cleanup
"""
from sys import version_info
import os
import xml.dom.minidom
import traceback
import math
import operator
import os.path
import json
import collections
import glob


#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

class cBinaryFile:
    def __init__(self, file):
        self.file = file
        self.infile = open(file, 'rb')
        self.ungetted = []

    def byte(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte or inbyte == '':
            self.infile.close()
            return None
        return ord(inbyte)

    def bytes(self, size):
        if size <= len(self.ungetted):
            result = self.ungetted[0:size]
            del self.ungetted[0:size]
            return result
        inbytes = self.infile.read(size - len(self.ungetted))
        if inbytes == '':
            self.infile.close()
        if type(inbytes) == type(''):
            result = self.ungetted + [ord(b) for b in inbytes]
        else:
            result = self.ungetted + [b for b in inbytes]
        self.ungetted = []
        return result

    def unget(self, byte):
        self.ungetted.append(byte)

    def ungets(self, bytes):
        bytes.reverse()
        self.ungetted.extend(bytes)

class cPDFDate:
    def __init__(self):
        self.state = 0

    def parse(self, char):
        if char == 'D':
            self.state = 1
            return None
        elif self.state == 1:
            if char == ':':
                self.state = 2
                self.digits1 = ''
            else:
                self.state = 0
            return None
        elif self.state == 2:
            if len(self.digits1) < 14:
                if char >= '0' and char <= '9':
                    self.digits1 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif char == '+' or char == '-' or char == 'Z':
                self.state = 3
                self.digits2 = ''
                self.TZ = char
                return None
            elif char == '"':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            elif char < '0' or char > '9':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            else:
                self.state = 0
                return None
        elif self.state == 3:
            if len(self.digits2) < 2:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) == 2:
                if char == "'":
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) < 5:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    if len(self.digits2) == 5:
                        self.state = 0
                        self.date = 'D:' + self.digits1 + self.TZ + self.digits2
                        return self.date
                    else:
                        return None
                else:
                    self.state = 0
                    return None

def fEntropy(countByte, countTotal):
    x = float(countByte) / countTotal
    if x > 0:
        return - x * math.log(x, 2)
    else:
        return 0.0

class cEntropy:
    def __init__(self):
        self.allBucket = [0 for i in range(0, 256)]
        self.streamBucket = [0 for i in range(0, 256)]

    def add(self, byte, insideStream):
        self.allBucket[byte] += 1
        if insideStream:
            self.streamBucket[byte] += 1

    def removeInsideStream(self, byte):
        if self.streamBucket[byte] > 0:
            self.streamBucket[byte] -= 1

    def calc(self):
        self.nonStreamBucket = map(operator.sub, self.allBucket, self.streamBucket)
        allCount = sum(self.allBucket)
        streamCount = sum(self.streamBucket)
        nonStreamCount = sum(self.nonStreamBucket)
        if streamCount == 0:
            return (allCount, sum(map(lambda x: fEntropy(x, allCount), self.allBucket)), streamCount, None,
                    nonStreamCount, sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)))
        else:
            return (allCount, sum(map(lambda x: fEntropy(x, allCount), self.allBucket)), streamCount,
                    sum(map(lambda x: fEntropy(x, streamCount), self.streamBucket)), nonStreamCount,
                    sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)))

class cPDFEOF:
    def __init__(self):
        self.token = ''
        self.cntEOFs = 0

    def parse(self, char):
        if self.cntEOFs > 0:
            self.cntCharsAfterLastEOF += 1
        if self.token == '' and char == '%':
            self.token += char
            return
        elif self.token == '%' and char == '%':
            self.token += char
            return
        elif self.token == '%%' and char == 'E':
            self.token += char
            return
        elif self.token == '%%E' and char == 'O':
            self.token += char
            return
        elif self.token == '%%EO' and char == 'F':
            self.token += char
            return
        elif self.token == '%%EOF' and (char == '\n' or char == '\r' or char == ' ' or char == '\t'):
            self.cntEOFs += 1
            self.cntCharsAfterLastEOF = 0
            if char == '\n':
                self.token = ''
            else:
                self.token += char
            return
        elif self.token == '%%EOF\r':
            if char == '\n':
                self.cntCharsAfterLastEOF = 0
            self.token = ''
        else:
            self.token = ''

def FindPDFHeaderRelaxed(oBinaryFile):
    bytes = oBinaryFile.bytes(1024)
    index = ''.join([chr(byte) for byte in bytes]).find('%PDF')
    if index == -1:
        oBinaryFile.ungets(bytes)
        return ([], None)
    for endHeader in range(index + 4, index + 4 + 10):
        if bytes[endHeader] == 10 or bytes[endHeader] == 13:
            break
    oBinaryFile.ungets(bytes[endHeader:])
    return (bytes[0:endHeader], ''.join([chr(byte) for byte in bytes[index:endHeader]]))

def Hexcode2String(char):
    if type(char) == int:
        return '#%02x' % char
    else:
        return char

def SwapCase(char):
    if type(char) == int:
        return ord(chr(char).swapcase())
    else:
        return char.swapcase()

def HexcodeName2String(hexcodeName):
    return ''.join(map(Hexcode2String, hexcodeName))

def SwapName(wordExact):
    return map(SwapCase, wordExact)

def UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut):
    if word != '':
        if slash + word in words:
            words[slash + word][0] += 1
            if hexcode:
                words[slash + word][1] += 1
        elif slash == '/' and allNames:
            words[slash + word] = [1, 0]
            if hexcode:
                words[slash + word][1] += 1
        if slash == '/':
            lastName = slash + word
        if slash == '':
            if word == 'stream':
                insideStream = True
            if word == 'endstream':
                if insideStream == True and oEntropy != None:
                    for char in 'endstream':
                        oEntropy.removeInsideStream(ord(char))
                insideStream = False
        if fOut != None:
            if slash == '/' and '/' + word in ('/JS', '/JavaScript', '/AA', '/OpenAction', '/JBIG2Decode', '/RichMedia', '/Launch'):
                wordExactSwapped = HexcodeName2String(SwapName(wordExact))
                fOut.write(C2BIP3(wordExactSwapped))
                print('/%s -> /%s' % (HexcodeName2String(wordExact), wordExactSwapped))
            else:
                fOut.write(C2BIP3(HexcodeName2String(wordExact)))
    return ('', [], False, lastName, insideStream)

class cCVE_2009_3459:
    def __init__(self):
        self.count = 0

    def Check(self, lastName, word):
        if (lastName == '/Colors' and word.isdigit() and int(word) > 2^24): # decided to alert when the number of colors is expressed with more than 3 bytes
            self.count += 1

def XMLAddAttribute(xmlDoc, name, value=None):
    att = xmlDoc.createAttribute(name)
    xmlDoc.documentElement.setAttributeNode(att)
    if value != None:
        att.nodeValue = value
    return att

def PDFiD(file, additional_keywords, allNames=False, extraData=False, force=False):
    """Example of XML output:
    <PDFiD ErrorOccured="False" ErrorMessage="" Filename="test.pdf" Header="%PDF-1.1" IsPDF="True" Version="0.0.4" Entropy="4.28">
            <Keywords>
                    <Keyword Count="7" HexcodeCount="0" Name="obj"/>
                    <Keyword Count="7" HexcodeCount="0" Name="endobj"/>
                    <Keyword Count="1" HexcodeCount="0" Name="stream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="endstream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="xref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="trailer"/>
                    <Keyword Count="1" HexcodeCount="0" Name="startxref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/Page"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/Encrypt"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JS"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JavaScript"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/AA"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/OpenAction"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/JBIG2Decode"/>
            </Keywords>
            <Dates>
                    <Date Value="D:20090128132916+01'00" Name="/ModDate"/>
            </Dates>
    </PDFiD>
    """

    word = ''
    wordExact = []
    hexcode = False
    lastName = ''
    insideStream = False
    keywords = ['obj',
                'endobj',
                'stream',
                'endstream',
                'xref',
                'trailer',
                'startxref',
                '/Page',
                '/Encrypt',
                '/ObjStm',
                '/JS',
                '/JavaScript',
                '/AA',
                '/OpenAction',
                '/AcroForm',
                '/JBIG2Decode',
                '/RichMedia',
                '/Launch',
                '/EmbeddedFile',
                '/XFA',
               ]
    words = {}
    dates = []
    for extrakeyword in additional_keywords:
        keywords.append(extrakeyword)
    for keyword in keywords:
        words[keyword] = [0, 0]
    slash = ''
    xmlDoc = xml.dom.minidom.getDOMImplementation().createDocument(None, 'PDFiD', None)
    XMLAddAttribute(xmlDoc, 'Version', __version__)
    XMLAddAttribute(xmlDoc, 'Filename', file)
    attErrorOccured = XMLAddAttribute(xmlDoc, 'ErrorOccured', 'False')
    attErrorMessage = XMLAddAttribute(xmlDoc, 'ErrorMessage', '')

    oPDFDate = None
    oEntropy = None
    oPDFEOF = None
    oCVE_2009_3459 = cCVE_2009_3459()
    try:
        attIsPDF = xmlDoc.createAttribute('IsPDF')
        xmlDoc.documentElement.setAttributeNode(attIsPDF)
        oBinaryFile = cBinaryFile(file)
        if extraData:
            oPDFDate = cPDFDate()
            oEntropy = cEntropy()
            oPDFEOF = cPDFEOF()
        (bytesHeader, pdfHeader) = FindPDFHeaderRelaxed(oBinaryFile)
        fOut = None
        if oEntropy != None:
            for byteHeader in bytesHeader:
                oEntropy.add(byteHeader, insideStream)
        if pdfHeader == None and not force:
            attIsPDF.nodeValue = 'False'
            return xmlDoc
        else:
            if pdfHeader == None:
                attIsPDF.nodeValue = 'False'
                pdfHeader = ''
            else:
                attIsPDF.nodeValue = 'True'
            att = xmlDoc.createAttribute('Header')
            att.nodeValue = repr(pdfHeader[0:10]).strip("'")
            xmlDoc.documentElement.setAttributeNode(att)
        byte = oBinaryFile.byte()
        while byte != None:
            char = chr(byte)
            charUpper = char.upper()
            if charUpper >= 'A' and charUpper <= 'Z' or charUpper >= '0' and charUpper <= '9':
                word += char
                wordExact.append(char)
            elif slash == '/' and char == '#':
                d1 = oBinaryFile.byte()
                if d1 != None:
                    d2 = oBinaryFile.byte()
                    if d2 != None and (chr(d1) >= '0' and chr(d1) <= '9' or chr(d1).upper() >= 'A' and chr(d1).upper() <= 'F') and (chr(d2) >= '0' and chr(d2) <= '9' or chr(d2).upper() >= 'A' and chr(d2).upper() <= 'F'):
                        word += chr(int(chr(d1) + chr(d2), 16))
                        wordExact.append(int(chr(d1) + chr(d2), 16))
                        hexcode = True
                        if oEntropy != None:
                            oEntropy.add(d1, insideStream)
                            oEntropy.add(d2, insideStream)
                        if oPDFEOF != None:
                            oPDFEOF.parse(d1)
                            oPDFEOF.parse(d2)
                    else:
                        oBinaryFile.unget(d2)
                        oBinaryFile.unget(d1)
                        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                else:
                    oBinaryFile.unget(d1)
                    (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
            else:
                oCVE_2009_3459.Check(lastName, word)

                (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                if char == '/':
                    slash = '/'
                else:
                    slash = ''

            if oPDFDate != None and oPDFDate.parse(char) != None:
                dates.append([oPDFDate.date, lastName])

            if oEntropy != None:
                oEntropy.add(byte, insideStream)

            if oPDFEOF != None:
                oPDFEOF.parse(char)

            byte = oBinaryFile.byte()
        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)

        # check to see if file ended with %%EOF.  If so, we can reset charsAfterLastEOF and add one to EOF count.  This is never performed in
        # the parse function because it never gets called due to hitting the end of file.
        if byte == None and oPDFEOF != None:
            if oPDFEOF.token == '%%EOF':
                oPDFEOF.cntEOFs += 1
                oPDFEOF.cntCharsAfterLastEOF = 0
                oPDFEOF.token = ''
    except:
        attErrorOccured.nodeValue = 'True'
        attErrorMessage.nodeValue = traceback.format_exc()

    attEntropyAll = xmlDoc.createAttribute('TotalEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyAll)
    attCountAll = xmlDoc.createAttribute('TotalCount')
    xmlDoc.documentElement.setAttributeNode(attCountAll)
    attEntropyStream = xmlDoc.createAttribute('StreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyStream)
    attCountStream = xmlDoc.createAttribute('StreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountStream)
    attEntropyNonStream = xmlDoc.createAttribute('NonStreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyNonStream)
    attCountNonStream = xmlDoc.createAttribute('NonStreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountNonStream)
    if oEntropy != None:
        (countAll, entropyAll , countStream, entropyStream, countNonStream, entropyNonStream) = oEntropy.calc()
        attEntropyAll.nodeValue = '%f' % entropyAll
        attCountAll.nodeValue = '%d' % countAll
        if entropyStream == None:
            attEntropyStream.nodeValue = 'N/A     '
        else:
            attEntropyStream.nodeValue = '%f' % entropyStream
        attCountStream.nodeValue = '%d' % countStream
        attEntropyNonStream.nodeValue = '%f' % entropyNonStream
        attCountNonStream.nodeValue = '%d' % countNonStream
    else:
        attEntropyAll.nodeValue = ''
        attCountAll.nodeValue = ''
        attEntropyStream.nodeValue = ''
        attCountStream.nodeValue = ''
        attEntropyNonStream.nodeValue = ''
        attCountNonStream.nodeValue = ''
    attCountEOF = xmlDoc.createAttribute('CountEOF')
    xmlDoc.documentElement.setAttributeNode(attCountEOF)
    attCountCharsAfterLastEOF = xmlDoc.createAttribute('CountCharsAfterLastEOF')
    xmlDoc.documentElement.setAttributeNode(attCountCharsAfterLastEOF)
    if oPDFEOF != None:
        attCountEOF.nodeValue = '%d' % oPDFEOF.cntEOFs
        if oPDFEOF.cntEOFs > 0:
            attCountCharsAfterLastEOF.nodeValue = '%d' % oPDFEOF.cntCharsAfterLastEOF
        else:
            attCountCharsAfterLastEOF.nodeValue = ''
    else:
        attCountEOF.nodeValue = ''
        attCountCharsAfterLastEOF.nodeValue = ''

    eleKeywords = xmlDoc.createElement('Keywords')
    xmlDoc.documentElement.appendChild(eleKeywords)
    for keyword in keywords:
        eleKeyword = xmlDoc.createElement('Keyword')
        eleKeywords.appendChild(eleKeyword)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = keyword
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('Count')
        att.nodeValue = str(words[keyword][0])
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('HexcodeCount')
        att.nodeValue = str(words[keyword][1])
        eleKeyword.setAttributeNode(att)
    eleKeyword = xmlDoc.createElement('Keyword')
    eleKeywords.appendChild(eleKeyword)
    att = xmlDoc.createAttribute('Name')
    att.nodeValue = '/Colors > 2^24'
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('Count')
    att.nodeValue = str(oCVE_2009_3459.count)
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('HexcodeCount')
    att.nodeValue = str(0)
    eleKeyword.setAttributeNode(att)
    if allNames:
        keys = sorted(words.keys())
        for word in keys:
            if not word in keywords:
                eleKeyword = xmlDoc.createElement('Keyword')
                eleKeywords.appendChild(eleKeyword)
                att = xmlDoc.createAttribute('Name')
                att.nodeValue = word
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('Count')
                att.nodeValue = str(words[word][0])
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('HexcodeCount')
                att.nodeValue = str(words[word][1])
                eleKeyword.setAttributeNode(att)
    eleDates = xmlDoc.createElement('Dates')
    xmlDoc.documentElement.appendChild(eleDates)
    dates.sort(key=lambda x: x[0])
    for date in dates:
        eleDate = xmlDoc.createElement('Date')
        eleDates.appendChild(eleDate)
        att = xmlDoc.createAttribute('Value')
        att.nodeValue = date[0]
        eleDate.setAttributeNode(att)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = date[1]
        eleDate.setAttributeNode(att)
    return xmlDoc

def PDFiD2String(xmlDoc, force):
    """
    Modified by CSE to fit ASSEMBLYLINE Service
    """
    properties = ['obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref']
    result = 'PDFID,PDFiD Version %s \n' % (xmlDoc.documentElement.getAttribute('Version'))
    if xmlDoc.documentElement.getAttribute('ErrorOccured') == 'True':
        return result + '***Error occured***%s\n' % xmlDoc.documentElement.getAttribute('ErrorMessage')
    if not force and xmlDoc.documentElement.getAttribute('IsPDF') == 'False':
        return result + 'Not a PDF document\n'
    result += 'Properties,PDF Header,%s\n' % xmlDoc.documentElement.getAttribute('Header')
    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        if node.getAttribute('Name') in properties:
            result += 'Properties,%s,%d\n' % (node.getAttribute('Name'), int(node.getAttribute('Count')))
        else:
            if int(node.getAttribute('Count')) > 0:
                result += 'Flags,%s,%d' % (node.getAttribute('Name'), int(node.getAttribute('Count')))
                if int(node.getAttribute('HexcodeCount')) > 0:
                    result += ',%d' % int(node.getAttribute('HexcodeCount'))
                result += '\n'
    if xmlDoc.documentElement.getAttribute('CountEOF') != '':
        result += '%s,%d\n' % ('Properties,%%EOF', int(xmlDoc.documentElement.getAttribute('CountEOF')))
    if xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF') != '':
        result += '%s,%d\n' % ('Properties,After last %%EOF', int(xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')))
    for node in xmlDoc.documentElement.getElementsByTagName('Dates')[0].childNodes:
        result += '%s,%s\n' % ('Properties,'+node.getAttribute('Name'), node.getAttribute('Value'))
    if xmlDoc.documentElement.getAttribute('TotalEntropy') != '':
        result += 'Entropy,Total,%s,%s bytes\n' % (xmlDoc.documentElement.getAttribute('TotalEntropy'), xmlDoc.documentElement.getAttribute('TotalCount'))
    if xmlDoc.documentElement.getAttribute('StreamEntropy') != '':
        result += 'Entropy,Inside streams,%s,%s bytes\n' % (xmlDoc.documentElement.getAttribute('StreamEntropy'), xmlDoc.documentElement.getAttribute('StreamCount'))
    if xmlDoc.documentElement.getAttribute('NonStreamEntropy') != '':
        result += 'Entropy,Outside streams,%s,%s bytes' % (xmlDoc.documentElement.getAttribute('NonStreamEntropy'), xmlDoc.documentElement.getAttribute('NonStreamCount'))
    return result

class cCount():
    def __init__(self, count, hexcode):
        self.count = count
        self.hexcode = hexcode

class cPDFiD():
    def __init__(self, xmlDoc, force):
        self.version = xmlDoc.documentElement.getAttribute('Version')
        self.filename = xmlDoc.documentElement.getAttribute('Filename')
        self.errorOccured = xmlDoc.documentElement.getAttribute('ErrorOccured') == 'True'
        self.errorMessage = xmlDoc.documentElement.getAttribute('ErrorMessage')
        self.isPDF = None
        if self.errorOccured:
            return
        self.isPDF = xmlDoc.documentElement.getAttribute('IsPDF') == 'True'
        if not force and not self.isPDF:
            return
        self.header = xmlDoc.documentElement.getAttribute('Header')
        self.keywords = {}
        for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
            self.keywords[node.getAttribute('Name')] = cCount(int(node.getAttribute('Count')), int(node.getAttribute('HexcodeCount')))
        self.obj = self.keywords['obj']
        self.endobj = self.keywords['endobj']
        self.stream = self.keywords['stream']
        self.endstream = self.keywords['endstream']
        self.xref = self.keywords['xref']
        self.trailer = self.keywords['trailer']
        self.startxref = self.keywords['startxref']
        self.page = self.keywords['/Page']
        self.encrypt = self.keywords['/Encrypt']
        self.objstm = self.keywords['/ObjStm']
        self.js = self.keywords['/JS']
        self.javascript = self.keywords['/JavaScript']
        self.aa = self.keywords['/AA']
        self.openaction = self.keywords['/OpenAction']
        self.acroform = self.keywords['/AcroForm']
        self.jbig2decode = self.keywords['/JBIG2Decode']
        self.richmedia = self.keywords['/RichMedia']
        self.launch = self.keywords['/Launch']
        self.embeddedfile = self.keywords['/EmbeddedFile']
        self.xfa = self.keywords['/XFA']
        self.colors_gt_2_24 = self.keywords['/Colors > 2^24']

        self.non_stream_entropy = float(xmlDoc.documentElement.getAttribute('NonStreamEntropy'))
        try:
            self.last_eof_bytes = int((xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')))
        except:
            self.last_eof_bytes = 0

def Quote(value, separator, quote):
    if isinstance(value, str):
        if separator in value:
            return quote + value + quote
    return value

def MakeCSVLine(fields, separator=';', quote='"'):
    formatstring = separator.join([field[0] for field in fields])
    strings = [Quote(field[1], separator, quote) for field in fields]
    return formatstring % tuple(strings)

def ProcessFile(filename, options, plugins):
    """
    Modified by CSE to fit ASSEMBLYLINE Service
    """
    results = []
    errors = set()

    xmlDoc = PDFiD(filename, options.get('additional_keywords'), options.get('all'), options.get('extra'), options.get('force'))
    strresult = PDFiD2String(xmlDoc, options.get('force')).split('\n')
    for l in strresult:
        if l.startswith('***Error occured***'):
            errors.add(l)
        results.append(l)

    if plugins == [] and options.get('select') == '':
        return results, errors

    oPDFiD = cPDFiD(xmlDoc, options.get('force'))

    for cPlugin in plugins:
        if not cPlugin.onlyValidPDF or not oPDFiD.errorOccured and oPDFiD.isPDF:
            try:
                oPlugin = cPlugin(oPDFiD)
            except Exception as e:
                errors.add('***Error occured***Error instantiating plugin: %s. Error: %s' % (cPlugin.name, e))
                continue

            try:
                score, hits = oPlugin.Score()
            except Exception as e:
                errors.add('***Error occured***Error running plugin: %s. Error: %s' % (cPlugin.name, e))
                continue

            if score >= options.get('minimumscore'):
                plresult = 'Plugin,%s,%d' % (cPlugin.name.replace("plugin", "").strip(), score)
                try:
                    plresult += ',Instructions: %s' % (oPlugin.Instructions(score, hits))
                except AttributeError:
                    pass
                results.append(plresult)
    return results, errors

#function derived from: http://blog.9bplus.com/pdfidpy-output-to-json
def PDFiD2JSON(xmlDoc, force):
    #Get Top Layer Data
    errorOccured = xmlDoc.documentElement.getAttribute('ErrorOccured')
    errorMessage = xmlDoc.documentElement.getAttribute('ErrorMessage')
    filename = xmlDoc.documentElement.getAttribute('Filename')
    header = xmlDoc.documentElement.getAttribute('Header')
    isPdf = xmlDoc.documentElement.getAttribute('IsPDF')
    version = xmlDoc.documentElement.getAttribute('Version')
    entropy = xmlDoc.documentElement.getAttribute('Entropy')

    #extra data
    countEof = xmlDoc.documentElement.getAttribute('CountEOF')
    countChatAfterLastEof = xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')
    totalEntropy = xmlDoc.documentElement.getAttribute('TotalEntropy')
    streamEntropy = xmlDoc.documentElement.getAttribute('StreamEntropy')
    nonStreamEntropy = xmlDoc.documentElement.getAttribute('NonStreamEntropy')

    keywords = []
    dates = []

    #grab all keywords
    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        name = node.getAttribute('Name')
        count = int(node.getAttribute('Count'))
        if int(node.getAttribute('HexcodeCount')) > 0:
            hexCount = int(node.getAttribute('HexcodeCount'))
        else:
            hexCount = 0
        keyword = { 'count':count, 'hexcodecount':hexCount, 'name':name }
        keywords.append(keyword)

    #grab all date information
    for node in xmlDoc.documentElement.getElementsByTagName('Dates')[0].childNodes:
        name = node.getAttribute('Name')
        value = node.getAttribute('Value')
        date = { 'name':name, 'value':value }
        dates.append(date)

    data = { 'countEof':countEof, 'countChatAfterLastEof':countChatAfterLastEof, 'totalEntropy':totalEntropy, 'streamEntropy':streamEntropy, 'nonStreamEntropy':nonStreamEntropy, 'errorOccured':errorOccured, 'errorMessage':errorMessage, 'filename':filename, 'header':header, 'isPdf':isPdf, 'version':version, 'entropy':entropy, 'keywords': { 'keyword': keywords }, 'dates': { 'date':dates} }
    complete = [ { 'pdfid' : data} ]
    result = json.dumps(complete)
    return result

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return list(map(lambda line:line.rstrip('\n'), f.readlines()))
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def AddPlugin(cClass):
    global plugins

    plugins.append(cClass)

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cPluginParent():
    onlyValidPDF = True

def LoadPlugins(plugins):
    errors = set()
    if len(plugins) == 0:
        return errors
    scriptPath = '/opt/al/pkg/'
    for plugin in sum(map(ProcessAt, plugins), []):
        try:
            if not plugin.lower().endswith('.py'):
                plugin += '.py'
            if not os.path.exists(plugin):
                scriptPlugin = os.path.join(scriptPath, plugin)
                if os.path.exists(scriptPlugin):
                    plugin = scriptPlugin
            exec(open(plugin, 'r').read())
        except Exception as e:
            errors.add('Error loading plugin: %s. Error: %s' % (plugin, e))

    return errors


def PDFiDMain(filename, additional_keywords, heuristics, deep_scan=False):
    """PDFiD Main Module. Modified by CSE to fit ASSEMBLYLINE Service.

    Args:
        filename: Original PDF sample path.
        additional_keywords: Additional keyword content for PDFId module to search in sample.
        heuristics: List of PDFId plugins.
        deep_scan: Not currently used.

    Returns:
        PDFId result (dictionary object) and error list.
    """
    global plugins
    plugins = []

    all_names = False
    # This appears to report on all keywords, which output is extensive, turning off
    #if deep_scan:
        #all_names = True

    # Options
    options = {
        'all': all_names,
        'force': True,
        'verbose': False,
        'extra': True,
        'literal': False,
        'select': '',
        'minimumscore': 1,
        'additional_keywords': [x for x in additional_keywords]
    }

    all_errors = set()

    plerrors = LoadPlugins(heuristics)
    for e in plerrors:
        all_errors.add(e)

    results, errors = ProcessFile(filename, options, plugins)
    for e in errors:
        all_errors.add(e.replace('***Error occured***', ""))

    dict_results = {}
    for r in results:
        rtype = r.split(',', 1)[0]
        rlist = r.split(',', 1)[1].split(",")
        if rtype in dict_results:
            dict_results[rtype].append(rlist)
        else:
            dict_results[rtype] = [rlist]

    return dict_results, all_errors
