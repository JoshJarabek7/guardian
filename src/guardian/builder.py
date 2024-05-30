"""Contains the ClamAVScannerBuilder class, which follows the builder design pattern to configure the scanner options"""
from .scanner import ClamAVScanner

class ClamAVScannerBuilder:
    """
    Builder class for configuring ClamAVScanner options.

    Options:
    - command (str): The ClamAV command to use (default: "clamscan").
    - database_path (str): The path to the ClamAV database (default: "/usr/local/share/clamav").
    - file_path (str): The path to the file or directory to scan (default: None).
    - in_memory (bool): Whether to scan files in memory or on disk (default: False).
    - verbose (bool): Enable verbose output (default: False).
    - archive_verbose (bool): Show filenames inside scanned archives (default: False).
    - debug (bool): Enable libclamav's debug messages (default: False).
    - quiet (bool): Only output error messages (default: False).
    - stdout (bool): Write to stdout instead of stderr (default: False).
    - no_summary (bool): Disable summary at end of scanning (default: False).
    - infected (bool): Only print infected files (default: False).
    - suppress_ok_results (bool): Skip printing OK files (default: False).
    - bell (bool): Sound bell on virus detection (default: False).
    - tempdir (str): Create temporary files in the specified directory (default: None).
    - leave_temps (bool): Do not remove temporary files (default: False).
    - gen_json (bool): Generate JSON metadata for the scanned files (default: False).
    - recursive (bool): Scan subdirectories recursively (default: False).
    - allmatch (bool): Continue scanning within file after finding a match (default: False).
    - cross_fs (bool): Scan files and directories on other filesystems (default: True).
    - follow_dir_symlinks (int): Follow directory symlinks (0 = never, 1 = direct, 2 = always) (default: 1).
    - follow_file_symlinks (int): Follow file symlinks (0 = never, 1 = direct, 2 = always) (default: 1).
    - file_list (str): Scan files from the specified file list (default: None).
    - remove (bool): Remove infected files (default: False).
    - move (str): Move infected files to the specified directory (default: None).
    - copy (str): Copy infected files to the specified directory (default: None).
    - exclude (str): Don't scan file names matching the specified regular expression (default: None).
    - exclude_dir (str): Don't scan directories matching the specified regular expression (default: None).
    - include (str): Only scan file names matching the specified regular expression (default: None).
    - include_dir (str): Only scan directories matching the specified regular expression (default: None).
    - bytecode (bool): Load bytecode from the database (default: True).
    - bytecode_unsigned (bool): Load unsigned bytecode (default: False).
    - bytecode_timeout (int): Set bytecode timeout in milliseconds (default: None).
    - statistics (int): Collect and print execution statistics (0 = none, 1 = bytecode, 2 = pcre) (default: 0).
    - detect_pua (bool): Detect Possibly Unwanted Applications (default: False).
    - exclude_pua (str): Skip PUA signatures of category CAT (default: None).
    - include_pua (str): Load PUA sigs of category CAT (default: None).
    - detect_structured (bool): Detect structured data, ex: SSN, Credit Card (default: False).
    - structured_ssn_format (int): SSN format (0 = normal, 1 = stripped, 2 = both) (default: None).
    - structured_ssn_count (int): Min SSN count to generate a detect (default: None).
    - structured_cc_count (int): Min CC count to generate a detect (default: None).
    - scan_mail (bool): Scan mail files (default: True).
    - phishing_sigs (bool): Enable email signature-based phising detection (default: True).
    - phising_scan_urls (bool): Enable URL signatured-base phising detection (default: True).
    - heuristic_alerts (bool): Heuristic alerts (default: True).
    - heuristic_scan_precedence (bool): Stop scanning as soon as a heuristic match is found (default: False).
    - normalize (bool): Normalize html, script, and text files... put false for yara compatibility (default: True).
    - scan_pe (bool): Scan PE files (default: True).
    - scan_elf (bool): Scan ELF files (default: True).
    - scan_ole2 (bool): Scan OLE2 containers (default: True).
    - scan_pdf (bool): Scan PDF files (default: True).
    - scan_swf (bool): Scan SWF files (default: True).
    - scan_html (bool): Scan HTML files (default: True).
    - scan_xmldocs (bool): Scan XML-based document files (default: True).
    - scan_hwp3 (bool): Scan HWP3 files (default: True).
    - scan_onenote (bool): Scan OneNote files (default: True).
    - scan_archive (bool): Scan archive files [supported by libclamav] (default: True).
    - alert_broken (bool): Alert on broken executable files [PE & ELF] (default: False).
    - alert_broken_media (bool): Alert on broken graphics files [JPEG, TIFF, PNG, GIF] (default: False).
    - alert_encrypted (bool): Alert on encrypted archives and documents (default: False).
    - alert_encrypted_archive (bool): Alert on encrypted archives (default: False).
    - alert_encrypted_doc (bool): Alert on encrypted documents (default: False).
    - alert_macros (bool): Alert on OLE2 files containing VBA macros (default: False).
    - alert_exceeds_max (bool): Alert on files that exceed max file size, max scan size, or max recursion limit (default: False).
    - alert_phising_ssl (bool): Alert on emails containing SSL mismatches in URLs (default: False).
    - alert_phising_cloak (bool): Alert on emails containing cloaked URLs (default: False).
    - alert_partition_intersection (bool): Alert on raw DMG image files containing partition intersections (default: False).
    - nocerts (bool): Disable authenticode certificate chain verification in PE files (default: None).
    - dumpcerts (bool): Dump authenticode certificate chain in PE files (default: None).
    - max_scantime (int): Scan time longer than this will be skipped and assumed clean [milliseconds] (default: None).
    - max_filesize (int): Files larger than this will be skipped and assumed clean [bytes] (default: None).
    - max_scansize (int): The maximum of data to scan for each container file [bytes] (default: None).
    - max_files (int): The maximum number of files to scan for each container file (default: None).



    TODO Some of the options are bool in python, but the actual string is yes/no. Be sure to handle it correctly.
    TODO Fill in the rest of the flag methods here and on scanner class.
    """

    def __init__(self):
        self.command = "clamscan"
        self.database_path = "/usr/local/share/clamav"
        self.file_path = None
        self.in_memory = False
        self.verbose = False
        self.archive_verbose = False
        self.debug = False
        self.quiet = False
        self.stdout = False
        self.no_summary = False
        self.infected = False
        self.suppress_ok_results = False
        self.bell = False
        self.tempdir = None
        self.leave_temps = False
        self.gen_json = False
        self.recursive = False
        self.allmatch = False
        self.cross_fs = True
        self.follow_dir_symlinks = 1
        self.follow_file_symlinks = 1
        self.file_list = None
        self.remove = False
        self.move = None
        self.copy = None
        self.exclude = None
        self.exclude_dir = None
        self.include = None
        self.include_dir = None

    def with_command(self, command):
        self.command = command
        return self

    def with_database_path(self, path):
        self.database_path = path
        return self

    def with_file_path(self, path):
        self.file_path = path
        return self

    def with_in_memory(self, in_memory):
        self.in_memory = in_memory
        return self

    def with_verbose(self, verbose):
        self.verbose = verbose
        return self

    def with_archive_verbose(self, archive_verbose):
        self.archive_verbose = archive_verbose
        return self

    def with_debug(self, debug):
        self.debug = debug
        return self

    def with_quiet(self, quiet):
        self.quiet = quiet
        return self

    def with_stdout(self, stdout):
        self.stdout = stdout
        return self

    def with_no_summary(self, no_summary):
        self.no_summary = no_summary
        return self

    def with_infected(self, infected):
        self.infected = infected
        return self

    def with_suppress_ok_results(self, suppress_ok_results):
        self.suppress_ok_results = suppress_ok_results
        return self

    def with_bell(self, bell):
        self.bell = bell
        return self

    def with_tempdir(self, tempdir):
        self.tempdir = tempdir
        return self

    def with_leave_temps(self, leave_temps):
        self.leave_temps = leave_temps
        return self

    def with_gen_json(self, gen_json):
        self.gen_json = gen_json
        return self

    def with_recursive(self, recursive):
        self.recursive = recursive
        return self

    def with_allmatch(self, allmatch):
        self.allmatch = allmatch
        return self

    def with_cross_fs(self, cross_fs):
        self.cross_fs = cross_fs
        return self

    def with_follow_dir_symlinks(self, follow_dir_symlinks):
        self.follow_dir_symlinks = follow_dir_symlinks
        return self

    def with_follow_file_symlinks(self, follow_file_symlinks):
        self.follow_file_symlinks = follow_file_symlinks
        return self

    def with_file_list(self, file_list):
        self.file_list = file_list
        return self

    def with_remove(self, remove):
        self.remove = remove
        return self

    def with_move(self, move):
        self.move = move
        return self

    def with_copy(self, copy):
        self.copy = copy
        return self

    def with_exclude(self, exclude):
        self.exclude = exclude
        return self

    def with_exclude_dir(self, exclude_dir):
        self.exclude_dir = exclude_dir
        return self

    def with_include(self, include):
        self.include = include
        return self

    def with_include_dir(self, include_dir):
        self.include_dir = include_dir
        return self

    def build(self):
        return ClamAVScanner(
            command=self.command,
            database_path=self.database_path,
            file_path=self.file_path,
            in_memory=self.in_memory,
            verbose=self.verbose,
            archive_verbose=self.archive_verbose,
            debug=self.debug,
            quiet=self.quiet,
            stdout=self.stdout,
            no_summary=self.no_summary,
            infected=self.infected,
            suppress_ok_results=self.suppress_ok_results,
            bell=self.bell,
            tempdir=self.tempdir,
            leave_temps=self.leave_temps,
            gen_json=self.gen_json,
            recursive=self.recursive,
            allmatch=self.allmatch,
            cross_fs=self.cross_fs,
            follow_dir_symlinks=self.follow_dir_symlinks,
            follow_file_symlinks=self.follow_file_symlinks,
            file_list=self.file_list,
            remove=self.remove,
            move=self.move,
            copy=self.copy,
            exclude=self.exclude,
            exclude_dir=self.exclude_dir,
            include=self.include,
            include_dir=self.include_dir
        )