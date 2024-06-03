"""Contains the ClamAVScannerBuilder class, which follows the builder design pattern to configure the scanner options"""
from pydantic import BaseModel
from typing import List
from .guardian_logger import guardian_logger

class ClamAVScannerOptions(BaseModel):
    """ Builder class for configuring ClamAVScanner options.

    Attributes:

        - command (str): The ClamAV command to use (default: "clamscan")
        - database (str): The path to the ClamAV database (default: "/usr/local/share/clamav")
        - file_path (str): The path to the file or directory to scan (default: None)
        - in_memory (bool): Whether to scan files in memory or on disk (default: False)
        - verbose (bool): Enable verbose output (default: False)
        - archive_verbose (bool): Show filenames inside scanned archives (default: False)
        - debug (bool): Enable libclamav's debug messages (default: False)
        - quiet (bool): Only output error messages (default: False)
        - stdout (bool): Write to stdout instead of stderr (default: False)
        - no_summary (bool): Disable summary at end of scanning (default: False)
        - infected (bool): Only print infected files (default: False)
        - suppress_ok_results (bool): Skip printing OK files (default: False)
        - bell (bool): Sound bell on virus detection (default: False)
        - tempdir (str): Create temporary files in the specified directory (default: None)
        - leave_temps (bool): Do not remove temporary files (default: False)
        - gen_json (bool): Generate JSON metadata for the scanned files (default: False)
        - recursive (bool): Scan subdirectories recursively (default: False)
        - allmatch (bool): Continue scanning within file after finding a match (default: False)
        - cross_fs (bool): Scan files and directories on other filesystems (default: True)
        - follow_dir_symlinks (int): Follow directory symlinks (0 = never, 1 = direct, 2 = always) (default: 1)
        - follow_file_symlinks (int): Follow file symlinks (0 = never, 1 = direct, 2 = always) (default: 1)
        - file_list (str): Scan files from the specified file list (default: None)
        - remove (bool): Remove infected files (default: False)
        - move (str): Move infected files to the specified directory (default: None)
        - copy (str): Copy infected files to the specified directory (default: None)
        - exclude (str): Don't scan file names matching the specified regular expression (default: None)
        - exclude_dir (str): Don't scan directories matching the specified regular expression (default: None)
        - include (str): Only scan file names matching the specified regular expression (default: None)
        - include_dir (str): Only scan directories matching the specified regular expression (default: None)
        - bytecode (bool): Load bytecode from the database (default: True)
        - bytecode_unsigned (bool): Load unsigned bytecode (default: False)
        - bytecode_timeout (int): Set bytecode timeout in milliseconds (default: None)
        - statistics (int): Collect and print execution statistics (0 = none, 1 = bytecode, 2 = pcre) (default: 0)
        - detect_pua (bool): Detect Possibly Unwanted Applications (default: False)
        - exclude_pua (str): Skip PUA signatures of category CAT (default: None)
        - include_pua (str): Load PUA sigs of category CAT (default: None)
        - detect_structured (bool): Detect structured data, ex: SSN, Credit Card (default: False)
        - structured_ssn_format (int): SSN format (0 = normal, 1 = stripped, 2 = both) (default: None)
        - structured_ssn_count (int): Min SSN count to generate a detect (default: None)
        - structured_cc_count (int): Min CC count to generate a detect (default: None)
        - scan_mail (bool): Scan mail files (default: True)
        - phishing_sigs (bool): Enable email signature-based phising detection (default: True)
        - phishing_scan_urls (bool): Enable URL signatured-base phising detection (default: True)
        - heuristic_alerts (bool): Heuristic alerts (default: True)
        - heuristic_scan_precedence (bool): Stop scanning as soon as a heuristic match is found (default: False)
        - normalize (bool): Normalize html, script, and text files... put false for yara compatibility (default: True)
        - scan_pe (bool): Scan PE files (default: True)
        - scan_elf (bool): Scan ELF files (default: True)
        - scan_ole2 (bool): Scan OLE2 containers (default: True)
        - scan_pdf (bool): Scan PDF files (default: True)
        - scan_swf (bool): Scan SWF files (default: True)
        - scan_html (bool): Scan HTML files (default: True)
        - scan_xmldocs (bool): Scan XML-based document files (default: True)
        - scan_hwp3 (bool): Scan HWP3 files (default: True)
        - scan_onenote (bool): Scan OneNote files (default: True)
        - scan_archive (bool): Scan archive files [supported by libclamav] (default: True)
        - alert_broken (bool): Alert on broken executable files [PE & ELF] (default: False)
        - alert_broken_media (bool): Alert on broken graphics files [JPEG, TIFF, PNG, GIF] (default: False)
        - alert_encrypted (bool): Alert on encrypted archives and documents (default: False)
        - alert_encrypted_archive (bool): Alert on encrypted archives (default: False)
        - alert_encrypted_doc (bool): Alert on encrypted documents (default: False)
        - alert_macros (bool): Alert on OLE2 files containing VBA macros (default: False)
        - alert_exceeds_max (bool): Alert on files that exceed max file size, max scan size, or max recursion limit (default: False)
        - alert_phishing_ssl (bool): Alert on emails containing SSL mismatches in URLs (default: False)
        - alert_phishing_cloak (bool): Alert on emails containing cloaked URLs (default: False)
        - alert_partition_intersection (bool): Alert on raw DMG image files containing partition intersections (default: False)
        - nocerts (bool): Disable authenticode certificate chain verification in PE files (default: None)
        - dumpcerts (bool): Dump authenticode certificate chain in PE files (default: None)
        - max_scantime (int): Scan time longer than this will be skipped and assumed clean [milliseconds] (default: None)
        - max_filesize (int): Files larger than this will be skipped and assumed clean [bytes] (default: None)
        - max_scansize (int): The maximum of data to scan for each container file [bytes] (default: None)
        - max_files (int): The maximum number of files to scan for each container file (default: None)
        - max_recursion (int): Maximum archive recursion level for container file (default: None)
        - max_dir_recursion (int): Maximum directory recursion level (default: None)
        - max_embeddedpe (int): Maximum size file to check for embedded PE (default: None)
        - max_htmlnormalize (int): Maximum size of HTML file to normalize (default: None)
        - max_htmlnotags (int): Maximum size of normalized HTML file to scan (default: None)
        - max_scriptnormalize (int): Maximum size of script file to normalize (default: None)
        - max_ziptypercg (int): Maximum size zip to reanalyze (default: None)
        - max_partitions (int): Maximum number of partitions in disk image to be scanned (default: None)
        - max_iconspe (int): Maximum number of icons in PE file to be scanned (default: None)
        - max_rechwp3 (int): Maximum recursive calls to HWP3 parsing function (default: None)
        - pcre_match_limit (int): Maxmium calls to the PCRE match function (default: None)
        - pcre_recmatch_limit (int): Maximum recursive calls to the PCRE match function (default: None)
        - pcre_max_filesize (int): Maximum size file to perform PCRE subsig matching (default: None)
        - disable_cache (bool): Disable caching and cache checks for hash sums of scanned files (default: None)
    """

    # None ClamAV related
    command: str = "command"
    file_path: str = None
    in_memory: bool = False

    # ClamAV Flags
    verbose: bool = None
    archive_verbose: bool = None
    debug: bool = None
    quiet: bool = None
    stdout: bool = None
    no_summary: bool = None
    infected: bool = None
    suppress_ok_results: bool = None
    bell: bool = None

    tempdir: str = None
    leave_temps: bool = False
    gen_json: bool = False

    database: str = "/usr/local/share/clamav"
    recursive: bool = False
    allmatch: bool = False
    cross_fs: bool = True
    follow_dir_symlinks: int = 1
    follow_file_symlinks: int = 1
    file_list: str = None
    remove: bool = False
    move: str = None
    copy: str = None
    exclude: str = None
    exclude_dir: str = None
    include: str = None
    include_dir: str = None
    bytecode: bool = True
    bytecode_unsigned: bool = False
    bytecode_timeout: int = None
    statistics: int = 0
    detect_pua: bool = False
    exclude_pua: str = None
    include_pua: str = None
    detect_structured: bool = False
    structured_ssn_format: int = None
    structured_ssn_count: int = None
    structured_cc_count: int = None
    scan_mail: bool = True
    phishing_sigs: bool = True
    phishing_scan_urls: bool = True
    heuristic_alerts: bool = True
    heuristic_scan_precedence: bool = False
    normalize: bool = True
    scan_pe: bool = True
    scan_elf: bool = True
    scan_ole2: bool = True
    scan_pdf: bool = True
    scan_swf: bool = True
    scan_html: bool = True
    scan_xmldocs: bool = True
    scan_hwp3: bool = True
    scan_onenote: bool = True
    scan_archive: bool = True
    alert_broken: bool = False
    alert_broken_media: bool = False
    alert_encrypted: bool = False
    alert_encrypted_archive: bool = False
    alert_encrypted_doc: bool = False
    alert_macros: bool = False
    alert_exceeds_max: bool = False
    alert_phishing_ssl: bool = False
    alert_phishing_cloak: bool = False
    alert_partition_intersection: bool = False
    nocerts: bool = None
    dumpcerts: bool = None
    max_scantime: int = None
    max_filesize: int = None
    max_scansize: int = None
    max_files: int = None

    def build_command_list(self) -> List[str]:
        """Builds a list of command arguments based on the set attributes.

        Returns:
            List[str]: A list of command-line arguments for ClamAV.
        """

        command_list = [self.command]
        pure_flags = set([
            "verbose",
            "archive_verbose",
            "debug",
            "quiet",
            "stdout",
            "no_summary",
            "infected",
            "suppress_ok_results",
            "bell",
            "nocerts", 
            "dumpcerts", 
            "disable_cache"
            ]) # The attributes with no value passed and are purely flags
        for field_name, field_value in self:

            # Handle pure flags
            if field_name in pure_flags and field_value is not None:
                converted_name = field_name.replace("_", "-")
                command_list.append(f"--{converted_name}")
                command_list.append(field_value)

            # Handle booleans
            elif field_name not in pure_flags and field_value is not None:
                if type(field_value) is bool:
                    command_list.append(f"--{field_name.replace("_", "-")}={'yes' if field_value == True else 'no'}")
                else:
                    command_list.extend([f"--{field_name.replace("_", "-")}={field_value}"])
            
            # Check if any edge cases missed
            else:
                guardian_logger.debug(f"Field Name: {field_name}    Field Value: {field_value}")
        
        return command_list

