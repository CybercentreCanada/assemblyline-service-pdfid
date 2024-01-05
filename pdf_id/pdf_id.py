from __future__ import annotations

import hashlib
import os
import re
import zlib
from collections.abc import Iterable
from copy import deepcopy
from typing import TYPE_CHECKING

from assemblyline.common.dict_utils import recursive_update
from assemblyline.common.exceptions import NonRecoverableError
from assemblyline.odm.base import FULL_URI
from assemblyline_service_utilities.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from pdf_id.pdfid import pdfid
from pdf_id.pdfparser import pdf_parser

if TYPE_CHECKING:
    from typing import Any


def convert_tags(tags: dict[str, Iterable[bytes]]) -> dict[str, list[str]]:
    return {tag_type: [tag.decode() for tag in tag_set] for tag_type, tag_set in tags.items()}


class PDFId(ServiceBase):
    def __init__(self, config: dict | None = None) -> None:
        super(PDFId, self).__init__(config)

    def execute(self, request: ServiceRequest) -> None:
        """Main Module. See README for details."""
        max_size = self.config.get("MAX_PDF_SIZE", 3000000)
        request.result = result = Result()
        if (os.path.getsize(request.file_path) or 0) < max_size or request.deep_scan:
            section = ResultSection("PDF Analysis of the file was skipped because the file is too big (limit is 3 MB).")
            section.set_heuristic(10)
            result.add_section(section)
            return

        path = request.file_path
        working_dir = self.working_directory

        # CALL PDFID and identify all suspicious keyword streams
        additional_keywords = self.config.get("ADDITIONAL_KEYS", [])
        heur = deepcopy(self.config.get("HEURISTICS", []))
        all_errors = set()

        res_txt = "Main Document Results"
        res, contains_objstms, errors = self.analyze_pdf(request, res_txt, path, working_dir, heur, additional_keywords)
        result.add_section(res)

        all_errors.update(errors)

        #  ObjStms: Treat all ObjStms like a standalone PDF document
        if contains_objstms:
            objstm_files = self.analyze_objstm(path, working_dir, request.deep_scan)
            obj_cnt = 1
            for osf in objstm_files:
                parent_obj = os.path.basename(osf).split("_")[1]
                res_txt = "ObjStream Object {0} from Parent Object {1}".format(obj_cnt, parent_obj)
                # It is going to look suspicious as the service created the PDF
                heur = [
                    x
                    for x in heur
                    if "plugin_suspicious_properties" not in x
                    and "plugin_embeddedfile" not in x
                    and "plugin_nameobfuscation" not in x
                ]

                res, contains_objstms, errors = self.analyze_pdf(
                    request, res_txt, osf, working_dir, heur, additional_keywords, get_malform=False
                )

                obj_cnt += 1
                result.add_section(res)

        if all_errors:
            erres = ResultSection(title_text="Errors Analyzing PDF")
            for e in all_errors:
                erres.add_line(e)
            result.add_section(erres)

        # pikepdf parsing
        self.additional_parsing(request)

    @staticmethod
    def get_pdfid(path, additional_keywords, plugins, deep: bool):
        """Run PDFId code on sample.

        Args:
            path: Original PDF sample path.
            additional_keywords: List of additional keywords to be searched (provided in service configuration).
            plugins: List of PDFId module plugins (provided in service configuration)..
            deep: Boolean value of AL submission deep scan value.

        Returns:
            PDFId result and error list.
        """
        options = {
            "verbose": False,
            "plugins": ",".join(plugins),
            "scan": False,
            "csv": False,
            "all": True,
            "extra": False,
            "force": False,
            "disarm": False,
            "minimumscore": 0.0,
            "select": "",
            "nozero": False,
            "output": "",
            "pluginoptions": "",
        }
        try:
            pdfid_result, errors = pdfid.PDFiDMain(path, options, additional_keywords, deep)
        except Exception as e:
            raise Exception(f"PDFID failed to run on sample. Error: {e}")

        # Process pdfid_results for service results
        pdfid_result_dict = {}
        for line in pdfid_result:
            if line:
                parts = line.split(",")
                value = parts[len(parts) - 1]
                for index in reversed(range(len(parts) - 1)):
                    value = {parts[index]: value}
                if isinstance(value, dict):
                    try:
                        pdfid_result_dict = recursive_update(pdfid_result_dict, value)
                    except Exception:
                        pass

        return pdfid_result_dict, errors

    def get_pdf_parser(self, path: str, working_dir: str, options: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
        """Run PDF Parser code on sample.

        Args:
            path: Original PDF sample path.
            working_dir: AL working directory.
            options: Dictionary of PDFId module options (see pdf_parser.py)

        Returns:
            PDF Parser result and error list.
        """
        op_cpy = options
        options = {
            "filter": "",
            "search": "",
            "reference": "",
            "decoders": "",
            "elements": "cxtsi",
            "type": "",
            "raw": False,
            "stats": False,
            "objstm": False,
            "verbose": False,
            "extract": f"{working_dir}/malformed",
            "hash": False,
            "nocanonicalizedoutput": False,
            "dump": f"{working_dir}/dump",
            "debug": True,
            "content": False,
            "unfiltered": False,
            "casesensitive": False,
            "regex": False,
            "overridingfilters": "",
            "generateembedded": 0,
            "generate": 0,
            "yara": None,
            "key": "",
            "object": "",
            "searchstream": "",
        }
        options.update(op_cpy)

        try:
            pdf_parser_statresult, errors = pdf_parser.PDFParserMain(path, working_dir, options)
        except Exception as e:
            pdf_parser_statresult = None
            errors = []
            self.log.error(f"pdf_parser failed to run on sample. Error: {e}")

        return pdf_parser_statresult, errors

    # noinspection PyBroadException
    def analyze_pdf(
        self,
        request: ServiceRequest,
        res_txt: str,
        path: str,
        working_dir: str,
        heur,
        additional_keywords,
        get_malform=True,
    ) -> tuple[ResultSection, bool, set]:
        """Extract metadata, keyword objects and content of interest from a PDF sample using PDFId, PDFId plugins,
        and PDF Parser.

        Args:
            request: AL request object.
            res_txt: Header string for AL result section title.
            path: Original PDF sample path.
            working_dir: AL working directory.
            heur: List of plugins to run on PDFId results (provided in service configuration).
            additional_keywords: List of additional keywords to be searched (provided in service configuration).
            get_malform: Extract malformed objects from PDF.

        Returns:
            AL result object, AL heuristics list to add to result, list of object streams (objstms), and an errors list.
        """
        triage_keywords = set()
        all_errors = set()
        embed_present = False
        objstms = False
        res = ResultSection(title_text=res_txt)
        carved_extracted_shas = set()

        if request.deep_scan:
            run_pdfparse = True
        else:
            run_pdfparse = False

        # Run PDFId
        try:
            pdfid_result, errors = self.get_pdfid([path], additional_keywords, heur, request.deep_scan)
        except Exception as e:
            raise NonRecoverableError(e)
        # Parse PDFId results
        pdfidres = ResultSection(title_text="PDFID Results", parent=res)
        if not pdfid_result:
            pdfidres.add_line("No results generated for file. Please see errors.")
        else:
            # Do not run for objstms, which are being analyzed when get_malform == False
            if get_malform:
                version = pdfid_result.get("PDFID", None)
                if version:
                    pdfidres.add_line(version)
                properties = pdfid_result.get("Properties", None)
                if properties:
                    pres = ResultSection(title_text="PDF Properties", parent=pdfidres)
                    for k, v in properties.items():
                        pres.add_line(f"{k}: {v}")
                        if k == "/ModDate":
                            pres.add_tag("file.pdf.date.modified", v)
                        elif k == "/CreationDate":
                            pres.add_tag("file.date.creation", v)
                        elif k == "/LastModified":
                            pres.add_tag("file.date.last_modified", v)
                        elif k == "/SourceModified":
                            pres.add_tag("file.pdf.date.source_modified", v)
                        elif k == "/pdfx":
                            pres.add_tag("file.pdf.date.pdfx", v)
                entropy = pdfid_result.get("Entropy", None)
                if entropy:
                    enres = ResultSection(title_text="Entropy", parent=pdfidres)
                    for enlist in entropy:
                        enres.add_line(f"{enlist[0]}: {enlist[1]}, ({enlist[2]})")
            flags = pdfid_result.get("Flags", None)
            if isinstance(flags, dict):
                fres = ResultSection(title_text="PDF Keyword Flags (Count)", parent=pdfidres)
                for k, v in flags.items():
                    if k == "/ObjStm":
                        objstms = True
                        # Filter out seemingly meaningless keywords
                    if ((not isinstance(v, dict) and int(v) > 1) or (isinstance(v, dict))) and len(k) > 2:
                        fres.add_line(f"{k}: {v}")
                    if k in additional_keywords:
                        triage_keywords.add(k.replace("/", "", 1))

            plugin = pdfid_result.get("Plugin", [])

            # If any plugin results, or flagged keywords found, run PDF Parser
            if plugin or triage_keywords:
                run_pdfparse = True

            for pllist in plugin:
                pl_name, pl_heur, pl_text = pllist
                pl_heur = int(pl_heur)
                pl_text = pl_text[14:]
                if not pl_text or pl_text == "None":
                    continue

                if pl_name in ["EmbeddedFile", "Name Obfuscation"]:
                    modres = ResultSection(title_text=pl_text, parent=pdfidres)

                    if pl_heur > 0:
                        modres.set_heuristic(pl_heur)

                    if pl_name == "EmbeddedFile":
                        embed_present = True

                elif pl_name in ["Triage", "Suspicious Properties"]:
                    javascript_found = False
                    for line in pl_text.splitlines():
                        lineres = ResultSection(title_text=line)
                        # Triage results
                        if "/JavaScript" in line:
                            triage_keywords.add("JavaScript")
                            if not javascript_found:
                                lineres.set_heuristic(19)
                                javascript_found = True
                        elif "/JS" in line:
                            triage_keywords.add("JS")
                            if not javascript_found:
                                lineres.set_heuristic(19)
                                javascript_found = True
                        elif "/JBIG2Decode" in line:
                            triage_keywords.add("JBIG2Decode")
                            lineres.set_heuristic(3)
                        elif "/Colors > 2^24" in line:
                            triage_keywords.add("Colors > 2^24")
                            lineres.set_heuristic(20)
                        elif "/AA" in line:
                            triage_keywords.add("AA")
                            lineres.set_heuristic(1)
                        elif "/Launch" in line:
                            triage_keywords.add("Launch")
                            lineres.set_heuristic(1)
                        elif "/OpenAction" in line:
                            triage_keywords.add("OpenAction")
                            lineres.set_heuristic(1)
                        elif "/GoToE" in line:
                            triage_keywords.add("GoToE")
                            lineres.set_heuristic(21)
                        elif "/GoToR" in line:
                            triage_keywords.add("GoToR")
                            lineres.set_heuristic(22)
                        elif "/Encrypt" in line:
                            triage_keywords.add("Encrypt")
                            lineres.set_heuristic(11)
                        elif "/AcroForm" in line:
                            triage_keywords.add("AcroForm")
                            lineres.set_heuristic(4)
                        elif "/RichMedia" in line:
                            triage_keywords.add("RichMedia")
                            lineres.set_heuristic(5)
                        elif "/XFA" in line:
                            triage_keywords.add("XFA")
                            lineres.set_heuristic(23)
                        elif "/Annot" in line:
                            triage_keywords.add("Annot")
                            lineres.set_heuristic(25)
                        elif "/ObjStm" in line:
                            triage_keywords.add("ObjStm")
                            lineres.set_heuristic(7)
                        elif "/URI" in line:
                            triage_keywords.add("URI")
                            lineres.set_heuristic(24)

                        # Suspicious properties results
                        elif "eof2" in line:
                            lineres.set_heuristic(2)
                        elif "eof5" in line:
                            lineres.set_heuristic(17)
                        elif "page" in line:
                            lineres.set_heuristic(26)
                        elif "entropy" in line:
                            lineres.set_heuristic(12)
                        elif "obj/endobj" in line:
                            lineres.set_heuristic(13)
                        elif "stream/endstream" in line:
                            lineres.set_heuristic(14)

                        if lineres.heuristic is not None:
                            pdfidres.add_subsection(lineres)

        for e in errors:
            all_errors.add(e)
            if e.startswith("Error running plugin"):
                self.log.warn(e)

        if run_pdfparse:
            # CALL PDF parser and extract further information
            pdf_parserres = ResultSection(title_text="PDF Parser Results")
            # STATISTICS
            # Do not run for objstms, which are being analyzed when get_malform == False
            if get_malform:
                options = {
                    "stats": True,
                }
                pdf_parser_result, errors = self.get_pdf_parser(path, working_dir, options)

                if pdf_parser_result:
                    if not pdf_parser_result:
                        pdf_parserres.add_line("No statistical results generated for file. Please see errors.")
                    else:
                        version = pdf_parser_result.get("version", None)
                        if version and version[0] != "0":
                            pdf_parserres.add_line(version[0])
                        stats = pdf_parser_result.get("stats", None)
                        if stats:
                            sres = ResultSection(
                                title_text="PDF Statistcs", parent=pdf_parserres, body_format=BODY_FORMAT.MEMORY_DUMP
                            )
                            for p in stats:
                                sres.add_line(p)
                    for e in errors:
                        all_errors.add(e)

            # Triage plugin -- search sample for keywords and carve content or extract object (if it contains a stream)
            carved_content = {}  # Format { "objnum": [{keyword: content list}}
            obj_extract_triage = set()
            jbig_objs = set()

            for keyword in triage_keywords:
                # ObjStms handled differently
                if keyword == "ObjStm":
                    continue

                options = {
                    "search": keyword,
                }
                pdf_parser_result, errors = self.get_pdf_parser(path, working_dir, options)

                if pdf_parser_result:
                    for p in pdf_parser_result["parts"]:
                        content = ""
                        references = []
                        # Trailer will be extracted anyways, try and grab all references anyways -- will be messy
                        if p.startswith("trailer:"):
                            # Grab the content after the keyword
                            # Check that keyword actually in content
                            if f"/{keyword}" in p:
                                try:
                                    content = p.split(keyword, 1)[1].replace(">>++>>", "").split("/", 1)[0].strip()
                                    references = re.findall("[0-9]* [0-9]* R", content)
                                except Exception:
                                    continue
                        # If not trailer, should be object
                        elif "Referencing:" in p:
                            # Grab the content after the keyword
                            if ">>++>>" in p:
                                try:
                                    content = p.split(keyword, 1)[1].replace(">>++>>", "").strip()
                                except Exception:
                                    try:
                                        content = p.split("\n", 3)[3]
                                    except Exception:
                                        content = p
                            else:
                                try:
                                    content = p.split("\n", 3)[3]
                                except Exception:
                                    content = p
                            # Sometimes the content is the same keyword with references (i.e "/URI /URI 10 0 R"
                            if content.startswith(f"/{keyword}"):
                                try:
                                    content = re.sub(f"/{keyword}[ ]*", "", content, 1)
                                except Exception:
                                    pass
                            try:
                                references = p.split("\n", 3)[2].replace("Referencing:", "").strip().split(", ")
                            except Exception:
                                pass
                        # Only extract JBIG2Decode objects with deep scan, but always report on their presence
                        if keyword == "JBIG2Decode" and "/Filter" in p and "Contains stream" in p:
                            try:
                                objnum = p.split("\n", 1)[0].split(" ")[1]
                                if request.deep_scan:
                                    obj_extract_triage.add(objnum)
                                jbig_objs.add(objnum)
                                continue
                            except Exception as e:
                                self.log.debug(e)
                                continue
                        # If no content, then keyword likely points to reference objects, so grab those
                        if content == "":
                            if references:
                                content = references
                            else:
                                # Something is wrong, drop it.
                                continue
                        else:
                            while True:
                                # Multiple references might be in a list, i.e. /Annot # # R vs. /Annots [# # R # # R]
                                islist = re.match(r"[s]?[ ]?\[([0-9]* [0-9]* R[ \\rn]{0,8})*\]", content)
                                if islist:
                                    content = re.sub(
                                        r"[\[\]]", "", islist.group(0).replace("s ", "").replace("R ", "R,")
                                    ).split(",")
                                    break
                                # References might be with instructions, i.e. [# # R /FitH null]
                                withinst = re.match(
                                    r"[s]?[ \\']{0,3}\[[ ]?([0-9]* [0-9]* R)[ \\rn]{1,8}" r"[/a-zA-Z0-9 ]*[ ]?\]",
                                    content,
                                )
                                if withinst:
                                    content = [withinst.group(1)]
                                    break
                                content = [content]
                                break
                        for c in content:
                            # If keyword = Javascript and content starts with '/JS', disregard as 'JS' will be extracted
                            if "JS" in triage_keywords and keyword == "JavaScript" and "/JS" in c[0:5]:
                                continue
                            if c in references or re.match("[0-9]* [0-9]* R", c):
                                try:
                                    ref_obj = c.split(" ", 1)[0]
                                    options = {"object": ref_obj, "get_object_detail": True}
                                    pdf_parser_subresult, err = self.get_pdf_parser(path, working_dir, options)

                                    if pdf_parser_subresult:
                                        for sub_p in pdf_parser_subresult["parts"]:
                                            sub_references = (
                                                sub_p.split("\n", 3)[2].replace("Referencing:", "").strip().split(", ")
                                            )
                                            ptyp = sub_p.split("\n", 2)[1].replace("Type:", "").strip().replace("/", "")
                                            # If the object contains a stream, extract the object.
                                            if "Contains stream" in sub_p:
                                                try:
                                                    objnum = sub_p.split("\n", 1)[0].split(" ")[1]
                                                    obj_extract_triage.add(objnum)
                                                except Exception:
                                                    pass
                                            # Or if the object Type is the keyword, grab all referenced objects.
                                            elif (
                                                sub_references[0] != "" and len(sub_references) >= 1 and ptyp == keyword
                                            ):
                                                for sr in sub_references:
                                                    try:
                                                        objnum = sr.split(" ", 1)[0]
                                                        obj_extract_triage.add(objnum)
                                                    except Exception:
                                                        pass
                                            # If not, extract object detail in to carved output
                                            elif pdf_parser_subresult["obj_details"] != "":
                                                try:
                                                    objnum = sub_p.split("\n", 1)[0].split(" ")[1]
                                                    if objnum in carved_content:
                                                        carved_content[objnum].append(
                                                            {keyword: pdf_parser_subresult["obj_details"]}
                                                        )
                                                    else:
                                                        carved_content[objnum] = [
                                                            {keyword: pdf_parser_subresult["obj_details"]}
                                                        ]
                                                except Exception:
                                                    continue

                                    for e in err:
                                        errors.add(e)
                                except Exception:
                                    # If none of that work, just extract the original object for examination.
                                    try:
                                        objnum = p.split("\n", 1)[0].split(" ")[1]
                                        obj_extract_triage.add(objnum)
                                    except Exception:
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
            show_content_of_interest = False
            if carved_content or jbig_objs:
                carres = ResultSection(title_text="Content of Interest")
            else:
                carres = None

            if jbig_objs:
                jbigres = ResultSection(
                    title_text="The following Object IDs are JBIG2DECODE streams:",
                    body_format=BODY_FORMAT.MEMORY_DUMP,
                    parent=carres,
                )
                jbigres.add_line(", ".join(map(str, jbig_objs)))
                show_content_of_interest = True

            if carved_content:
                carved_obj_size_limit = int(request.get_param("carved_obj_size_limit"))
                for k, l in sorted(carved_content.items()):
                    for d in l:
                        for keyw, con in d.items():
                            subres = ResultSection(title_text=f"Object {k}: Hits for Keyword '{keyw}':")
                            subres.set_heuristic(8)

                            con_bytes = con.encode()
                            if len(con) < carved_obj_size_limit:
                                subres.set_body(con, BODY_FORMAT.MEMORY_DUMP)

                                # Check for IOC content
                                patterns = PatternMatch()
                                st_value = patterns.ioc_match(con_bytes, bogon_ip=True)
                                if st_value:
                                    carres.add_subsection(subres)
                                    show_content_of_interest = True
                                    for ty, val in st_value.items():
                                        for v in val:
                                            subres.add_tag(ty, v)
                            else:
                                crv_sha = hashlib.sha256(con_bytes).hexdigest()
                                is_supplementary = keyw in ["URI"]
                                extraction_purpose = "as supplementary file" if is_supplementary else "for analysis"

                                if crv_sha not in carved_extracted_shas:
                                    f_name = f"carved_content_obj_{k}_{crv_sha[0:7]}"
                                    subres.add_lines(
                                        [
                                            f"Content over {carved_obj_size_limit} bytes it will be extracted {extraction_purpose}",
                                            f"Name: {f_name} - SHA256: {crv_sha}",
                                        ]
                                    )
                                    carres.add_subsection(subres)
                                    show_content_of_interest = True
                                    crvf = os.path.join(self.working_directory, f_name)
                                    with open(crvf, "wb") as f:
                                        f.write(con_bytes)
                                    try:
                                        if is_supplementary:
                                            # Add as supplementary
                                            request.add_supplementary(
                                                crvf, os.path.basename(crvf), f"Supplementary content from object {k}"
                                            )
                                        else:
                                            request.add_extracted(
                                                crvf,
                                                os.path.basename(crvf),
                                                f"Extracted content from object {k}",
                                                safelist_interface=self.api_interface,
                                            )
                                    except MaxExtractedExceeded:
                                        pass
                                    carved_extracted_shas.add(crv_sha)

            if show_content_of_interest:
                pdf_parserres.add_subsection(carres)

            # ELEMENTS
            # Do not show for objstms
            if get_malform:
                if request.deep_scan:
                    options = {"verbose": True, "nocanonicalizedoutput": True, "get_malform": get_malform}
                elif embed_present:
                    options = {"verbose": True, "elements": "ctsi", "type": "/EmbeddedFile", "get_malform": get_malform}
                else:
                    options = {"verbose": True, "elements": "cst", "get_malform": get_malform}
                pdf_parser_result, errors = self.get_pdf_parser(path, working_dir, options)

                embed_extracted = set()
                if pdf_parser_result:
                    if not pdf_parser_result:
                        pdf_parserres.add_line("No structure information generated for file. Please see errors.")
                    else:
                        # PDF Parser will write any malformed content over 100 bytes to a file
                        files = pdf_parser_result.get("files", None)
                        if files:
                            for f, l in files.items():
                                if f == "malformed":
                                    if l:
                                        pdf_parserres.set_heuristic(6)
                                    for i in l:
                                        try:
                                            request.add_extracted(
                                                i,
                                                os.path.basename(i),
                                                "Extracted malformed content in PDF Parser Analysis.",
                                                safelist_interface=self.api_interface,
                                            )
                                        except MaxExtractedExceeded:
                                            break

                        parts = pdf_parser_result.get("parts", None)
                        # Extract service will extract the sample's embedded files.
                        # However we want to make note of them so that they are not extracted again below
                        if parts:
                            for p in sorted(parts):
                                if "Type: /EmbeddedFile" in p:
                                    getobj = p.split("\n", 1)[0].split(" ")[1]
                                    embed_extracted.add(getobj)

                # Extract objects collected from above analysis
                obj_to_extract = obj_extract_triage - embed_extracted - jbig_objs

                if obj_to_extract:
                    options = {
                        "filter": True,
                        "object": obj_to_extract,
                        "dump": "extracted_obj_",
                    }
                    pdf_parser_result, errors = self.get_pdf_parser(path, working_dir, options)

                    if pdf_parser_result:
                        files = pdf_parser_result.get("files", None)
                        extracted_files = []
                        if files:
                            for f, l in files.items():
                                if f == "embedded":
                                    for i in l:
                                        f_name = os.path.basename(i)
                                        obj_id = f_name.replace("extracted_obj_", "")
                                        try:
                                            if request.add_extracted(
                                                i,
                                                f_name,
                                                f"Object {obj_id} extracted in PDF Parser Analysis.",
                                                safelist_interface=self.api_interface,
                                            ):
                                                extracted_files.append(f"Extracted object {obj_id} as {f_name}")
                                        except MaxExtractedExceeded:
                                            break
                        for e in errors:
                            all_errors.add(e)

                        if extracted_files:
                            extract_res = ResultSection(title_text="Extracted embedded objects", parent=pdf_parserres)
                            extract_res.set_heuristic(9)
                            extract_res.add_lines(extracted_files)

                # Extract jbig2decode objects in deep scan mode
                if request.deep_scan and len(jbig_objs) > 0:
                    options = {
                        "object": jbig_objs,
                        "dump": "extracted_jb_obj_",
                    }
                    pdf_parser_result, errors = self.get_pdf_parser(path, working_dir, options)

                    if pdf_parser_result:
                        extracted_jb = []
                        files = pdf_parser_result.get("files", None)
                        if files:
                            for f, l in files.items():
                                if f == "embedded":
                                    for i in l:
                                        f_name = os.path.basename(i)
                                        obj_id = f_name.replace("extracted_jb_obj_", "")
                                        extracted_jb.append(f"JBIG2DECODE object {obj_id} extracted as {f_name}")
                                        try:
                                            if request.add_extracted(
                                                i,
                                                f_name,
                                                f"JBIG2DECODE object {obj_id} extracted in PDF Parser Analysis.",
                                                safelist_interface=self.api_interface,
                                            ):
                                                extracted_jb.append(
                                                    f"JBIG2DECODE object {obj_id} extracted as {f_name}"
                                                )
                                        except MaxExtractedExceeded:
                                            break

                        for e in errors:
                            all_errors.add(e)

                        if extracted_jb:
                            jbig_extract_res = ResultSection(
                                title_text="Extracted JBIG2Decode objects", parent=pdf_parserres
                            )
                            jbig_extract_res.set_heuristic(9)
                            jbig_extract_res.add_lines(extracted_jb)

            if pdf_parserres.subsections:
                res.add_subsection(pdf_parserres)

        return res, objstms, all_errors

    def write_objstm(self, path: str, working_dir: str, objstm: str, objstm_path: str):
        """Write object stream (objstm) to file as a mock PDF.

        Args:
            path: Original PDF sample path.
            working_dir: AL working directory.
            objstm: Content of objstm.
            objstm_path: File path to write mock PDF.

        Returns:
            File path of objstm file if extraction successful, or None.
        """
        stream_present = False
        header = b"%PDF-1.6\x0A%Fake header created by AL PDFID service.\x0A"
        trailer = b"%%EOF\x0A"
        obj_footer = b"\rendobj\r"
        objstm_file = None

        options = {
            "object": objstm,
            "dump": objstm_path,
            "filter": True,
            "raw": True,
        }
        pdf_parser_subresult, _ = self.get_pdf_parser(path, working_dir, options)

        if pdf_parser_subresult:
            for sub_p in pdf_parser_subresult["parts"]:
                if len(sub_p.split("\n", 4)) >= 4 and sub_p.split("\n", 4)[3] == "Contains stream":
                    stream_present = True
                    break
            if stream_present:
                files = pdf_parser_subresult.get("files", None)
                if files:
                    for fi, l in files.items():
                        if fi == "embedded" and len(l) > 0:
                            objstm_file = l[0]
                            with open(objstm_file, "rb+") as f:
                                stream = f.read()
                                # Remove any extra content before objects
                                if not re.match(b"<<.*", stream):
                                    extra_content = re.match(rb"[^<]*", stream).group(0)
                                    stream = stream.replace(extra_content, b"%" + extra_content + b"\x0A")
                                obj_idx = 1
                                # Find all labels and surround them with obj headers
                                for lab in re.findall(rb"(<<[^\n]*>>[\x0A\x0D]|<<[^\n]*>>$)", stream):
                                    stream = stream.replace(
                                        lab,
                                        str(obj_idx).encode()
                                        + b" 0 obj\r"
                                        + b"".join(lab.rsplit(b"\n", 1))
                                        + obj_footer,
                                    )
                                    obj_idx += 1
                                # Find all streams and surround them wirh stream headers
                                for ste in re.findall(rb">>(?:(?!stream)(?![\r\n]endobj)[^<])+", stream):
                                    # Might be multi-layer stream:
                                    if ste.endswith(b">>"):
                                        continue
                                    stream = stream.replace(
                                        ste, b">>stream\n" + ste.replace(b">>", b"", 1) + b"\nendstream\rendobj\r"
                                    )
                                # Find all labels with attached stream, and surround them with obj headers
                                for lab_ste in re.findall(
                                    rb"(?:(?:(?!obj)...)|(?:endobj))([\r\n]<<(?:(?!endobj).)+)", stream, re.DOTALL
                                ):
                                    stream = stream.replace(
                                        lab_ste, b"\r" + str(obj_idx).encode() + b" 0 obj\r" + lab_ste[2:]
                                    )
                                    obj_idx += 1
                                f.seek(0, 0)
                                f.write(header + stream + trailer)

        return objstm_file

    def analyze_objstm(self, path: str, working_dir: str, deep_scan: bool) -> set:
        """Extract object streams (objstm) from PDF sample and write to file as a mock PDF.

        Args:
            path: Original PDF sample path.
            working_dir: AL working directory.
            deep_scan: Boolean value of AL submission deep scan value.

        Returns:
            List of extracted objstm file paths.
        """
        objstm_extracted: set[str] = set()

        obj_files = set()

        # Only extract first 2 if not deep scan
        max_obst = 100 if deep_scan else 1  # Really 2

        options_objstm = {"elements": "i", "type": "/ObjStm", "max_objstm": max_obst}

        pdf_parser_result, _ = self.get_pdf_parser(path, working_dir, options_objstm)
        parts = pdf_parser_result.get("parts", None) if pdf_parser_result else None

        idx = 0
        for p in sorted(p for p in parts if "Type: /ObjStm" in p):
            getobj = p.split("\n", 1)[0].split(" ")[1]
            if getobj in objstm_extracted:
                continue
            dump_file = os.path.join(self.working_directory, f"objstm_{getobj}_{idx}")
            idx += 1
            obj_file = self.write_objstm(path, working_dir, getobj, dump_file)
            if obj_file:
                objstm_extracted.add(getobj)
                obj_files.add(obj_file)

        return obj_files

    def additional_parsing(self, request: ServiceRequest) -> None:
        """Parses urls and scripts in streams"""
        streams = []
        dictionary: bytes
        stream_data: bytes
        for i, (dictionary, stream_data) in enumerate(
            re.findall(b"(?s)<<([^>]+)>>\nstream(.+?)endstream", request.file_contents)
        ):
            if b"/Filter" not in dictionary:
                streams.append(stream_data)
            elif b"/Filter /FlateDecode" in dictionary:
                try:
                    streams.append(zlib.decompress(stream_data.strip(b"\r\n")))
                except zlib.error as e:
                    self.log.error(f"{request.sha256} stream {i} /FlateDecode failed: {e}")
            else:  # TBD: Other encoding types
                pass
        all_streams = b"".join(streams)
        urls = self._get_annotation_urls(all_streams)
        scripts: list[bytes] = re.findall(rb"(?s)<script\b[^>]*>([^<].*?)</script\s*>", all_streams)
        patterns = PatternMatch()
        if urls:
            body = "\n".join(urls)
            request.result.add_section(
                ResultSection(
                    "URL in Annotations",
                    body=body,
                    heuristic=Heuristic(27),
                    tags=convert_tags(patterns.ioc_match(body.encode())),
                )
            )
        if scripts:
            all_scripts = b"\n".join(scripts)
            tags: dict[str, list[str]] = convert_tags(patterns.ioc_match(all_scripts))
            heuristic = Heuristic(28)
            if b"exportXFAData" in all_scripts:
                tags["attribution.exploit"] = ["CVE-2023-27363"]
                heuristic.add_signature_id("foxit")
            scripts_name = hashlib.sha256(all_scripts).hexdigest()[:8] + "_scripts.js"
            scripts_path = os.path.join(self.working_directory, scripts_name)
            try:
                with open(scripts_path, "wb") as f:
                    f.write(all_scripts)
                request.add_extracted(scripts_path, scripts_name, "Scripts extracted from PDF streams.")
            except MaxExtractedExceeded:
                pass
            except Exception as e:
                self.log.warning(f"Failed to write scripts file: {e}")
            request.result.add_section(ResultSection("PDF Scripts", heuristic=heuristic, tags=tags))

    def _get_annotation_urls(self, data: bytes) -> set[str]:
        urls: set[str] = set()
        url: bytes
        for url in re.findall(rb"/URI \(([^)]+)\)", data):
            try:
                url_string = url.decode("ascii")
            except UnicodeDecodeError:
                continue
            if re.match(FULL_URI, url_string):
                urls.add(url_string)
        return urls
