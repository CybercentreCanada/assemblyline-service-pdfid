from assemblyline.common.exceptions import NonRecoverableError
from assemblyline.al.common.result import Result, ResultSection, TEXT_FORMAT
from assemblyline.al.common.result import SCORE, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase


class PDFId(ServiceBase):
    SERVICE_ACCEPTS = 'document/pdf'
    SERVICE_CATEGORY = "Static Analysis"
    SERVICE_DESCRIPTION = "This service extracts metadata from PDFs using Didier Stevens PDFId & PDFParser."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256
    SERVICE_DEFAULT_CONFIG = {
        'ADDITIONAL_KEYS': ['/URI'],
        'HEURISTICS': [
            'plugin_embeddedfile',
            'plugin_nameobfuscation',
            'plugin_suspicious_properties',
            'plugin_triage',
        ],
        'MAX_PDF_SIZE': 3000000,
    }

    def __init__(self, cfg=None):
        super(PDFId, self).__init__(cfg)

    def import_service_deps(self):
        global os, pdid, pdfparser, re
        from pdfid import pdfid as pdid
        from pdfparser import pdf_parser as pdfparser
        import os
        import re
        try:
            from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch
            import unicodedata
            global PatternMatch, unicodedata
        except ImportError:
            pass

    def get_pdfid(self, path, additional_keywords, options, deep):

        try:
            pdfid_result, errors = pdid.PDFiDMain(path, additional_keywords, options, deep)
        except Exception as e:
            raise Exception("PDFID failed to run on sample. Error: {}" .format(e))

        return pdfid_result, errors

    def get_pdfparser(self, path, working_dir, options):
        try:
            pdfparser_statresult, errors = pdfparser.PDFParserMain(path, working_dir, **options)
        except Exception as e:
            raise Exception("PDFParser failed to run on sample. Error: {}" .format(e))

        return pdfparser_statresult, errors

    def analyze_pdf(self, request, res_txt, path, working_dir, heur, additional_keywords, get_malform=True):
        triage_keywords = []
        all_errors = set()
        objstms = False

        res = ResultSection(title_text=res_txt, score=SCORE.NULL)

        try:
            pdfid_result, errors = self.get_pdfid(path, additional_keywords, heur, request.deep_scan)
        except Exception as e:
            raise NonRecoverableError(e)

        pdfidres = ResultSection(title_text="PDFID Results", score=SCORE.NULL, parent=res)
        if len(pdfid_result) == 0:
            pdfidres.add_line("No results generated for file. Please see errors.")
        else:
            # Do not run for objstms, which are being analyzed when get_malform == False
            if get_malform:
                version = pdfid_result.get("PDFID", None)
                if version:
                    pdfidres.add_line(version[0])
                properties = pdfid_result.get("Properties", None)
                if properties:
                    pres = ResultSection(title_text="PDF Properties", score=SCORE.NULL, parent=pdfidres)
                    for plist in properties:
                        pres.add_line("{0}: {1}" .format(plist[0], plist[1]))
                        if plist[0] == "/ModDate":
                            pres.add_tag(TAG_TYPE['PDF_DATE_MOD'], plist[1], TAG_WEIGHT['MED'])
                        elif plist[0] == "/CreationDate":
                            pres.add_tag(TAG_TYPE['PDF_DATE_CREATION'], plist[1], TAG_WEIGHT['MED'])
                        elif plist[0] == "/LastModified":
                            pres.add_tag(TAG_TYPE['PDF_DATE_LASTMODIFIED'], plist[1], TAG_WEIGHT['MED'])
                        elif plist[0] == "/SourceModified":
                            pres.add_tag(TAG_TYPE['PDF_DATE_SOURCEMODIFIED'], plist[1], TAG_WEIGHT['MED'])
                        elif plist[0] == "/pdfx":
                            pres.add_tag(TAG_TYPE['PDF_DATE_PDFX'], plist[1], TAG_WEIGHT['MED'])
                entropy = pdfid_result.get("Entropy", None)
                if entropy:
                    enres = ResultSection(title_text="Entropy", score=SCORE.NULL, parent=pdfidres)
                    for enlist in entropy:
                        enres.add_line("{0}: {1}, ({2})" .format(enlist[0], enlist[1], enlist[2]))
            flags = pdfid_result.get("Flags", None)
            if flags:
                fres = ResultSection(title_text="PDF Keyword Flags", score=SCORE.NULL, parent=pdfidres)
                for flist in flags:
                    if flist[0] == "/ObjStm":
                        objstms = True
                    if len(flist) == 3:
                        fres.add_line("{0}:Count: {1}, Hex-Encoded Count: {2}" .format(flist[0], flist[1], flist[2]))
                    else:
                        fres.add_line("{0}:Count: {1}".format(flist[0], flist[1]))
            plugin = pdfid_result.get("Plugin", None)
            if plugin:
                plres = ResultSection(title_text="Plugin Results", score=SCORE.NULL, parent=pdfidres)
                for pllist in plugin:
                    modres = ResultSection(title_text=pllist[0], score=int(pllist[1]), parent=plres,
                                           body_format=TEXT_FORMAT.MEMORY_DUMP)
                    modres.add_line(pllist[2])
                    # Grab suspicious properties for pdfparser
                    if pllist[0] == 'Triage':
                        triage_keywords = [re.sub(r'(\"|:|/)', '', x) for x in
                                           re.findall(r'\"/[^\"]*\":', pllist[2], re.IGNORECASE)]

        for e in errors:
            all_errors.add(e)
            if e.startswith('Error running plugin'):
                self.log.warn(e)

        # CALL PDF parser and extract further information
        pdfparserres = ResultSection(title_text="PDF Parser Results", score=SCORE.NULL, parent=res)
        # STATISTICS
        # Do not run for objstms, which are being analyzed when get_malform == False
        if get_malform:
            options = {
                "stats": True,
            }
            try:
                pdfparser_result, errors = self.get_pdfparser(path, working_dir, options)
            except Exception as e:
                pdfparser_result = None
                self.log.debug(e)

            if pdfparser_result:
                if len(pdfparser_result) == 0:
                    pdfparserres.add_line("No statistical results generated for file. Please see errors.")
                else:
                    version = pdfparser_result.get("version", None)
                    if version:
                        pdfparserres.add_line(version[0])
                    stats = pdfparser_result.get("stats", None)
                    if stats:
                        sres = ResultSection(title_text="PDF Statistcs", score=SCORE.NULL, parent=pdfparserres,
                                             body_format=TEXT_FORMAT.MEMORY_DUMP)
                        for p in stats:
                            sres.add_line(p)
                for e in errors:
                    all_errors.add(e)

        # ELEMENTS
        if request.deep_scan:
            options = {
                "verbose": True,
                "nocanonicalizedoutput": True,
                "get_malform": get_malform
            }
        else:
            options = {
                "verbose": True,
                "elements": "ctsi",
                "type": "/EmbeddedFile",
                "get_malform": get_malform
            }
        try:
            pdfparser_result, errors = self.get_pdfparser(path, working_dir, options)
        except Exception as e:
            pdfparser_result = None
            self.log.debug(e)

        embed_extracted = set()
        if pdfparser_result:
            if len(pdfparser_result) == 0:
                pdfparserres.add_line("No structure information generated for file. Please see errors.")
            else:
                # PDF Parser will write any malformed content over 100 bytes to a file
                files = pdfparser_result.get("files", None)
                if files:
                    for f, l in files.iteritems():
                        if f == 'malformed':
                            for i in l:
                                request.add_extracted(i,  "Extracted malformed content in PDF Parser Analysis.")

                parts = pdfparser_result.get("parts", None)
                # Extract any embedded files
                if parts:
                    pres = ResultSection(title_text="PDF Elements", score=SCORE.NULL, parent=pdfparserres,
                                         body_format=TEXT_FORMAT.MEMORY_DUMP)
                    for p in sorted(parts):
                        # Do not show for objstms, which are being analyzed when get_malform == False
                        if get_malform:
                            pres.add_line(p)
                        if "Type: /EmbeddedFile" in p:
                            getobj = p.split("\n", 1)[0].split(" ")[1]
                            if getobj in embed_extracted:
                                continue
                            options = {
                                "filter": True,
                                "object": getobj,
                                "dump": "embedded_file_obj_{0}" .format(getobj),
                            }
                            try:
                                pdfparser_subresult, err = self.get_pdfparser(path, working_dir, options)
                            except Exception as e:
                                pdfparser_subresult = None
                                self.log.debug(e)
                            if pdfparser_subresult:
                                files = pdfparser_subresult.get("files", None)
                                if files:
                                    res.add_tag('FILE_STRING', "EmbeddedFile", weight=0)
                                    embed_extracted.add(getobj)
                                    for f, l in files.iteritems():
                                        if f == 'embedded':
                                            for i in l:
                                                request.add_extracted(i, "Extracted embedded file from obj {} "
                                                                         "in PDF Parser Analysis." .format(getobj))
                                for e in err:
                                    all_errors.add(e)

            for e in errors:
                all_errors.add(e)

        # Triage plugin -- search sample for keywords and carve content or extract object (if it contains a stream)
        carved_content = {}  # Format { "objnum": [{keyword: content list}}
        obj_extract_triage = set()

        for keyword in triage_keywords:
            res.add_tag('FILE_STRING', keyword, weight=0)
            # ObjStms handled differently
            if keyword == 'ObjStm':
                continue

            options = {
                "search": keyword,
            }
            try:
                pdfparser_result, errors = self.get_pdfparser(path, working_dir, options)
            except Exception as e:
                pdfparser_result = None
                self.log.debug(e)

            if pdfparser_result:
                for p in pdfparser_result['parts']:
                    # Trailer will be extracted anyways, try and grab all references anyways -- will be messy
                    if p.startswith("trailer:"):
                        # Grab the content after the keyword
                        content = p.split(keyword, 1)[1].replace('>>++>>', '').split("/", 1)[0].strip()
                        references = re.findall("[0-9]* [0-9]* R", content)
                    # If not trailer, should be object
                    elif 'Referencing:' in p:
                        # Grab the content after the keyword
                        if '>>++>>' in p:
                            try:
                                content = p.split(keyword, 1)[1].replace('>>++>>', '').strip()
                            except:
                                try:
                                    content = p.split("\n", 3)[3]
                                except:
                                    content = p
                        else:
                            try:
                                content = p.split("\n", 3)[3]
                            except:
                                content = p
                        # Sometimes the content is the same keyword with references (i.e "/URI /URI 10 0 R"
                        if content.startswith("/{}" .format(keyword)):
                            try:
                                content = re.sub("/{}[ ]*" .format(keyword), "", content, 1)
                            except:
                                pass
                        try:
                            references = p.split("\n", 3)[2].replace('Referencing:', '').strip().split(", ")
                        except:
                            references = []
                    else:
                        content = ""
                        references = []
                    # If no content, then keyword likely points to reference objects, so grab those
                    if content == '':
                        if len(references) > 0:
                            content = references
                        else:
                            # Something is wrong, drop it.
                            continue
                    # Multiple references might be in a list, i.e. /Annot # # R vs. /Annots [# # R, # # R]
                    else:
                        islist = re.match(r"[s]?[ ]?\[([0-9]* [0-9]* R[ ]{0,1})*\]", content)
                        if islist:
                            content = re.sub(r"\[|\]", "", islist.group(0).replace("s ", '')
                                             .replace("R ", "R,")).split(",")
                        else:
                            content = [content]
                    for c in content:
                        # If keyword is Javascript and content starts with '/JS', disregard as 'JS' will be extracted
                        if "JS" in triage_keywords and keyword == "JavaScript" and "/JS" in c[0:5]:
                            continue
                        if c in references or re.match("[0-9]* [0-9]* R"):
                            try:
                                ref_obj = c.split(" ", 1)[0]
                                options = {
                                    "object": ref_obj,
                                    "get_object_detail": True
                                }
                                try:
                                    pdfparser_subresult, err = self.get_pdfparser(path, working_dir, options)
                                except Exception as e:
                                    pdfparser_subresult = None
                                    self.log.debug(e)

                                if pdfparser_subresult:
                                    for sub_p in pdfparser_subresult['parts']:
                                        sub_references = sub_p.split("\n", 3)[2].replace('Referencing:', '').strip()\
                                            .split(", ")
                                        type = sub_p.split("\n", 2)[1].replace('Type:', '').strip().replace("/", "")
                                        # If the object contains a stream, extract the object.
                                        if "Contains stream" in sub_p:
                                            try:
                                                objnum = sub_p.split("\n", 1)[0].split(" ")[1]
                                                obj_extract_triage.add(objnum)
                                            except:
                                                pass
                                        # Or if the object Type is the keyword, grab all referenced objects.
                                        elif sub_references[0] != '' and len(sub_references) >= 1 \
                                                and type == keyword:
                                            for sr in sub_references:
                                                try:
                                                    objnum = sr.split(" ", 1)[0]
                                                    obj_extract_triage.add(objnum)
                                                except:
                                                    pass
                                        # If not, extract object detail in to carved output
                                        elif pdfparser_subresult['obj_details'] != "":
                                            try:
                                                objnum = sub_p.split("\n", 1)[0].split(" ")[1]
                                                if objnum in carved_content:
                                                    carved_content[objnum]\
                                                        .append({keyword: pdfparser_subresult['obj_details']})
                                                else:
                                                    carved_content[objnum] = \
                                                        [{keyword: pdfparser_subresult['obj_details']}]
                                            except:
                                                continue

                                for e in err:
                                    errors.add(e)
                            except:
                                # If none of that work, just extract the original object for examination.
                                try:
                                    objnum = p.split("\n", 1)[0].split(" ")[1]
                                    obj_extract_triage.add(objnum)
                                except:
                                    pass
                        # If content does not look like a reference:
                        else:
                            if p.startswith("trailer:"):
                                continue
                            objnum = p.split("\n", 1)[0].split(" ")[1]
                            # If the object contains a stream extract the object
                            if p.split("\n", 4)[3] == "Contains stream":
                                obj_extract_triage.add(objnum)
                            else:
                                # Or just carve the content
                                if objnum in carved_content:
                                    carved_content[objnum].append({keyword: c})
                                else:
                                    carved_content[objnum] = [{keyword: c}]

                for e in errors:
                    all_errors.add(e)

        # Add carved content to result output
        if len(carved_content) > 0:
            carres = ResultSection(title_text="Content of Interest", score=SCORE.NULL, parent=pdfparserres)
            for k, l in sorted(carved_content.iteritems()):
                carved_obj_idx = 0
                subres = ResultSection(title_text="From Object {}" .format(k), score=SCORE.NULL, parent=carres)
                for d in l:
                    for keyw, con in d.iteritems():
                        subresb = ResultSection(title_text="Content for Keyword hit:  '{}':".format(keyw),
                                                score=SCORE.NULL, body_format=TEXT_FORMAT.MEMORY_DUMP, parent=subres)
                        if len(con) < 500:
                            subresb.add_line(con)
                            # Check for IOC content
                            try:
                                patterns = PatternMatch()
                            except:
                                patterns = None
                            if patterns:
                                st_value = patterns.ioc_match(con, bogon_ip=True)
                                if len(st_value) > 0:
                                    for ty, val in st_value.iteritems():
                                        if val == "":
                                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                            subresb.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                        else:
                                            ulis = list(set(val))
                                            for v in ulis:
                                                subresb.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                        else:
                            subresb.add_line("Content over 500 bytes, see extracted files".format(keyw))
                            carvf = os.path.join(self.working_directory, "carved_content_obj_{0}_{1}_{2}"
                                                 .format(k, keyw, carved_obj_idx))
                            with open(carvf, 'wb') as f:
                                f.write(con)
                            request.add_extracted(carvf, "Extracted content from object {}" .format(k))
                            carved_obj_idx += 1

        # Extract objects collected from above analysis
        obj_to_extract = obj_extract_triage - embed_extracted
        for o in obj_to_extract:
            # Final check to ensure object has a stream, if not drop it.
            options = {
                "object": o
            }
            try:
                pdfparser_result, errors = self.get_pdfparser(path, working_dir, options)
            except Exception as e:
                pdfparser_result = None
                self.log.debug(e)
            if pdfparser_result:
                if not pdfparser_result['parts'][0].split("\n", 4)[3] == "Contains stream":
                    continue
            else:
                continue

            options = {
                "filter": True,
                "object": o,
                "dump": "extracted_obj_{}".format(o),
            }
            try:
                pdfparser_result, errors = self.get_pdfparser(path, working_dir, options)
            except Exception as e:
                pdfparser_result = None
                self.log.debug(e)

            if pdfparser_result:
                files = pdfparser_result.get("files", None)
                if files:
                    for f, l in files.iteritems():
                        if f == 'embedded':
                            for i in l:
                                request.add_extracted(i, "Object {} extracted in PDF Parser Analysis." .format(o))

                for e in errors:
                    all_errors.add(e)

        return res, objstms, all_errors

    def write_objstm(self, path, working_dir, objstm, objstm_path):

        stream_present = False
        header = "%PDF-1.5\x0A%Fake header created by AL PDFID service.\x0A"
        trailer = "%%EOF\x0A"
        obj_footer = "endobj\x0A"
        objstm_file = None

        options = {
            "object": objstm,
            "dump": objstm_path,
            "filter": True,
            "raw": True,
        }
        try:
            pdfparser_subresult, err = self.get_pdfparser(path, working_dir, options)
        except Exception as e:
            pdfparser_subresult = None
            self.log.debug(e)

        if pdfparser_subresult:
            for sub_p in pdfparser_subresult['parts']:
                if sub_p.split("\n", 4)[3] == "Contains stream":
                    stream_present = True
            if stream_present:
                files = pdfparser_subresult.get("files", None)
                if files:
                    for f, l in files.iteritems():
                        if f == 'embedded' and len(l) > 0:
                            objstm_file = l[0]
                            with open(objstm_file, 'r+') as f:
                                stream = f.read()
                                # Remove any extra content before objects
                                if not re.match("<<.*", stream):
                                    extra_content = re.match(r'[^<]*', stream).group(0)
                                    stream = stream.replace(extra_content, "%{}\x0A" .format(extra_content))
                                # Find all labels and surround them with obj headers
                                obj_idx = 1
                                for m in re.findall(r"(<<[^\n]*>>\x0A|<<[^\n]*>>$)", stream):
                                    stream = stream.replace(m, "{} 0 obj\x0A" .format(obj_idx) + m + obj_footer)
                                    obj_idx += 1
                                f.seek(0, 0)
                                f.write(header + stream + trailer)

        return objstm_file

    def analyze_objstm(self, path, working_dir, deep_scan):

        objstm_extracted = set()

        obj_files = set()
        options_objstm = {
            "elements": "i",
            "type": "/ObjStm",
        }

        try:
            pdfparser_result, errors = self.get_pdfparser(path, working_dir, options_objstm)
            parts = pdfparser_result.get("parts", None)
        except Exception as e:
            parts = None
            self.log.debug(e)

        # Only extract if less than 10
        if parts:
            if len(parts) < 2 or deep_scan:
                idx = 0
                for p in sorted(parts):
                    if "Type: /ObjStm" in p:
                        getobj = p.split("\n", 1)[0].split(" ")[1]
                        if getobj in objstm_extracted:
                            continue
                        dump_file = os.path.join(self.working_directory, "objstm_{0}_{1}" .format(getobj, idx))
                        idx += 1
                        obj_file = self.write_objstm(path, working_dir, getobj, dump_file)
                        if obj_file:
                            objstm_extracted.add(getobj)
                            obj_files.add(obj_file)

        return obj_files

    def execute(self, request):
        max_size = self.cfg['MAX_PDF_SIZE']
        result = Result()
        request.result = result
        if (request.task.size or 0) < max_size or request.deep_scan:
            path = request.download().encode('ascii', 'ignore')
            working_dir = self.working_directory

            # CALL PDFID and identify all suspicious keyword streams
            additional_keywords = self.cfg['ADDITIONAL_KEYS']
            heur = self.cfg['HEURISTICS']

            all_errors = set()

            res_txt = "Main Document Results"
            res, contains_objstms, errors = self.analyze_pdf(request, res_txt, path, working_dir, heur,
                                                             additional_keywords)
            result.add_result(res)

            for e in errors:
                all_errors.add(e)

            #  ObjStms: Treat all ObjStms like a standalone PDF document
            if contains_objstms:
                objstm_files = self.analyze_objstm(path, working_dir, request.deep_scan)
                obj_cnt = 1
                for osf in objstm_files:
                    parent_obj = osf.split("_")[1]
                    res_txt = "ObjStream Object {0} from Parent Object {1}" .format(obj_cnt, parent_obj)
                    # It is going to look suspicious as the service created the PDF
                    try:
                        heur.remove("plugin_suspicious_properties")
                    except:
                        pass
                    res, contains_objstms, errors = self.analyze_pdf(request, res_txt, osf, working_dir, heur,
                                                                     additional_keywords, get_malform=False)
                    if len(res.tags) > 0:
                        obj_cnt += 1
                        result.add_result(res)


            if len(all_errors) > 0:
                erres = ResultSection(title_text="Errors Analyzing PDF", score=SCORE.NULL)
                for e in all_errors:
                    erres.add_line(e)
                result.add_result(erres)

        else:
            request.result.add_section(ResultSection(SCORE['NULL'], "PDF Analysis of the file was"
                                                                    " skipped because the file is "
                                                                    "too big (limit is 3 MB)."))
