"""Contains the ClamAVScannerOptions class to configure the scanner options"""

from pydantic import BaseModel
from typing import List, Literal
from .guardian_logger import guardian_logger


PUA_TYPES = Literal[
    "Andr.Adware",
    "Andr.Downloader",
    "Andr.Dropper",
    "Andr.Tool",
    "Andr.Trojan",
    "Andr.Virus",
    "Cert.Revoked",
    "Doc.Dropper",
    "Doc.Packed",
    "Doc.Tool",
    "Doc.Trojan",
    "Email.Phishing",
    "Email.Trojan",
    "Embedded.File",
    "Html.Exploit",
    "Html.Tool",
    "Html.Trojan",
    "Java.Exploit",
    "Java.Packer",
    "Js.Exploit",
    "Osx.File",
    "Osx.Trojan",
    "Packed.Tool",
    "Pdf.Exploit",
    "Pdf.Trojan",
    "Php.Trojan",
    "Rtf.Exploit",
    "Spy.Tool",
    "Swf.Spyware",
    "Tool.Countermeasure",
    "Tool.Tool",
    "Unix.Adware",
    "Unix.Coinminer",
    "Unix.Downloader",
    "Unix.File",
    "Unix.Malware",
    "Unix.Tool",
    "Unix.Trojan",
    "Unix.Virus",
    "Win.Adware",
    "Win.Coinminer",
    "Win.Downloader",
    "Win.Dropper",
    "Win.Exploit",
    "Win.File",
    "Win.Ircbot",
    "Win.Joke",
    "Win.Keylogger",
    "Win.Malware",
    "Win.Packed",
    "Win.Packer",
    "Win.Proxy",
    "Win.Ransomware",
    "Win.Spyware",
    "Win.Tool",
    "Win.Trojan",
    "Win.Virus",
]

YON = Literal["yes", "no"]


class ClamAVScannerOptions(BaseModel):
    """Builder class for configuring ClamAVScanner options.

    Attributes:

        - command (str): The ClamAV command to use (default: "clamscan")


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

        - database (str): The path to the ClamAV database (default: "/usr/local/share/clamav")

        - log (str): Save scan report to FILE (default: None)

        - recursive (bool): Scan subdirectories recursively (default: False)
        - allmatch (bool): Continue scanning within file after finding a match (default: False)

        - cross_fs (str): Scan files and directories on other filesystems [yes/no] (default: yes)

        - follow_dir_symlinks (int): Follow directory symlinks. There are 3 options:
            - 0: Never follow directory symlinks.
            - 1 (default): Only follow directory symlinks, which are passed as direct arguments to clamscan.
            - 2: always follow directory symlinks.

        - follow_file_symlinks (int): Follow file symlinks. There are 3 options:
            - 0: Never follow file symlinks.
            - 1 (default): Only follow file symlinks, which are passed as direct arguments to clamscan.
            - 2: Always follow file symlinks.

        - file_list (str): Scan files from the specified file list (default: None)
        - remove (str): Remove infected files [yes/no] (default: no)
        - move (str): Move infected files to the specified directory (default: None)
        - copy (str): Copy infected files to the specified directory (default: None)
        - exclude (str): Don't scan file names matching the specified regular expression (default: None)
        - exclude_dir (str): Don't scan directories matching the specified regular expression (default: None)
        - include (str): Only scan file names matching the specified regular expression (default: None)
        - include_dir (str): Only scan directories matching the specified regular expression (default: None)
        - bytecode (str): With this option enabled ClamAV will load bytecode from the database. It is highly recommended you keep this option turned on, otherwise you may miss detections for many new viruses. [yes/no] (default: yes)
        - bytecode_unsigned (str): Allow loading bytecode from outside digitally signed .c[lv]d files. **Caution**: You should NEVER run bytecode signatures from untrusted sources. Doing so may result in arbitrary code execution. [yes/no] (default: no)
        - bytecode_timeout (int): Set bytecode timeout in milliseconds (default: 10000 = 10s)
        - statistics (str): Collect and print execution statistics [none/bytecode/pcre] (default: none)
        - detect_pua (str): Detect Possibly Unwanted Applications [yes/no] (default: no)
        - exclude_pua (str): Skip PUA signatures of category CAT (default: None)
        - include_pua (str): Load PUA sigs of category CAT (default: None)
        - detect_structured (bool): Detect structured data, ex: SSN, Credit Card [yes/no] (default: no)
        - structured_ssn_format (int): SSN format [0 = normal, 1 = stripped , 2 = both] (default: 0)
        - structured_ssn_count (int): Min SSN count to generate a detect (default: 3)
        - structured_cc_count (int): Min CC count to generate a detect (default: 3)
        - scan_mail (str): Scan mail files [yes/no] (default: yes)
        - phishing_sigs (str): Enable email signature-based phising detection [yes/no] (default: yes)
        - phishing_scan_urls (str): Enable URL signatured-base phising detection [yes/no] (default: yes)
        - heuristic_alerts (str): In some cases (eg. complex malware, exploits in graphic files, and others), ClamAV uses special algorithms to provide accurate detection. This option can be used to control the algorithmic detection. [yes/no] (default: yes)
        - heuristic_scan_precedence (str): Allow heuristic match to take precedence. When enabled, if a heuristic scan (such as phishingScan) detects a possible virus/phish it will stop scan immediately. Recommended, saves CPU scan-time. When disabled, virus/phish detected by heuristic scans will be reported only at the end of a scan. If an archive contains both a heuristically detected  virus/phish, and a real malware, the real malware will be reported Keep this disabled if you intend to handle "Heuristics.*" viruses  differently from "real" malware. If a non-heuristically-detected virus (signature-based) is found first, the scan is interrupted immediately, regardless of this config option. [yes/no] (default: no)
        - normalize (str): Normalize (compress whitespace, downcase, etc.) html, script, and text files. Use 'no' for yara compatibility. [yes/no] (default: yes)
        - scan_pe (str): PE stands for Portable Executable - it's an executable file format used in all 32-bit versions of Windows operating systems. By default ClamAV performs deeper analysis of executable files and attempts to decompress popular executable packers such as UPX, Petite, and FSG. If you turn off this option, the original files will still be scanned but without additional processing. [yes/no] (default: yes)
        - scan_elf (str): Executable and Linking Format is a standard format for UN*X executables. This option controls the ELF support. If you turn it off, the original files will still be scanned but without additional processing. [yes/no] (default: yes)
        - scan_ole2 (str): Scan Microsoft Office documents and .msi files. If you turn off this option, the original files will still be scanned but without additional processing. [yes/no] (default: yes)
        - scan_pdf (str): Scan within PDF files. If you turn off this option, the original files will still be scanned, but without decoding and additional processing.[yes/no] (default: yes)
        - scan_swf (str): Scan SWF files. If you turn off this option, the original files will still be scanned but without additional processing. [yes/no] (default: yes)
        - scan_html (str): Detect, normalize/decrypt and scan HTML files and embedded scripts. If you turn off this option, the original files will still be scanned, but without additional processing. [yes/no] (default: yes)
        - scan_xmldocs (str): Scan xml-based document files supported by libclamav. If you turn off this option, the original files will still be scanned, but without additional processing. [yes/no] (default: yes)
        - scan_hwp3 (str): Scan HWP3 files. If you turn off this option, the original files will still be scanned, but without additional processing. [yes/no] (default: yes)
        - scan_onenote (str): Scan OneNote files [yes/no] (default: yes)
        - scan_archive (str): Scan archives supported by libclamav. If you turn off this option, the original files will still be scanned, but without unpacking and additional processing. [yes/no] [supported by libclamav] (default: yes)

        - alert_broken (str): Alert on broken executable files (PE & ELF) [yes/no] (default: no)
        - alert_broken_media (str): Alert on broken graphics files (JPEG, TIFF, PNG, GIF) [yes/no] (default: no)
        - alert_encrypted (str): Alert on encrypted archives and documents [yes/no] (default: no)
        - alert_encrypted_archive (str): Alert on encrypted archives [yes/no] (default: no)
        - alert_encrypted_doc (str): Alert on encrypted documents [yes/no] (default: no)
        - alert_macros (str): Alert on OLE2 files containing VBA macros [yes/no] (default: no)
        - alert_exceeds_max (str): Alert on files that exceed max file size, max scan size, or max recursion limit [yes/no] (default: no)
        - alert_phishing_ssl (str): Alert on emails containing SSL mismatches in URLs [yes/no] (default: no)
        - alert_phishing_cloak (str): Alert on emails containing cloaked URLs [yes/no] (default: no)
        - alert_partition_intersection (str): Alert on raw DMG image files containing partition intersections [yes/no] (default: no)
        - nocerts (bool): Disable authenticode certificate chain verification in PE files (default: None)
        - dumpcerts (bool): Dump authenticode certificate chain in PE files (default: None)


        - max_scantime (int): The maximum time to scan before giving up. The value is in milliseconds. The value of 0 disables the limit. This option protects your system against DoS attacks [milliseconds] (default: 120000 = 120s or 2min)
        - max_filesize (int): Extract and scan at most #n bytes from each archive. You may pass the value in kilobytes in format xK or xk, or megabytes in format xM or xm, where x is a number. This option protects your system against DoS attacks [bytes] (default: 100M, max: 2GB)
        - max_scansize (int): Extract and scan at most #n bytes from each archive. The size the archive plus the sum of the sizes of all files within archive count toward the scan size. For example, a 1M uncompressed archive containing a single 1M inner file counts as 2M toward max-scansize. You may pass the value in kilobytes in format xK or xk, or megabytes in format xM or xm, where x is a number. This option protects your system against DoS attacks (default: 400M)
        - max_files (int): xtract at most #n files from each scanned file (when this is an archive, a document or another kind of container). This option protects your system against DoS attacks (default: 10000)
        - max_recursion (int): Set archive recursion level limit. This option protects your system against DoS attacks (default: 17)
        - max_dir_recursion (int): Maximum depth directories are scanned at (default: 15)
        - max_embeddedpe (int): Maximum size file to check for embedded PE. You may pass the value in kilobytes in format xK or xk, or megabytes in format xM or xm, where x is a number  (default: 40M)
        - max_htmlnormalize (int): Maximum size of HTML file to normalize. You may pass the value in kilobytes in format xK or xk, or megabytes in format xM or xm, where x is a number (default: 40M)
        - max_htmlnotags (int): Maximum size of normalized HTML file to scan. You may pass the value in kilobytes in format xK or xk, or megabytes in format xM or xm, where x is a number (default: 8M)
        - max_scriptnormalize (int): Maximum size of script file to normalize. You may pass the value in kilobytes in format xK or xk, or megabytes in format xM or xm, where x is a number (default: 20M)
        - max_ziptypercg (int): Maximum size zip to type reanalyze. You may pass the value in kilobytes in format xK or xk, or megabytes in format xM or xm, where x is a number (default: 1M)
        - max_partitions (int): This option sets the maximum number of partitions of a raw disk image to be scanned. This must be a positive integer (default: 50)
        - max_iconspe (int): This option sets the maximum number of icons within a PE to be scanned. This must be a positive integer (default: 100).
        - max_rechwp3 (int): This option sets the maximum recursive calls to HWP3 parsing function (default: 16).
        - pcre_match_limit (int): Maximum calls to the PCRE match function (default: 100000).
        - pcre_recmatch_limit (int): Maximum recursive calls to the PCRE match function (default: 2000).
        - pcre_max_filesize (int): Maximum size file to perform PCRE subsig matching (default: 100 MB).
        - disable_cache (bool): Disable caching and cache checks for hash sums of scanned files (default: None)
    """

    # Non-ClamAV related
    command: str = "clamscan"

    # ClamAV Flags
    verbose: bool = False
    archive_verbose: bool = False
    debug: bool = False
    quiet: bool = False
    stdout: bool = False
    no_summary: bool = False
    infected: bool = False
    suppress_ok_results: bool = False
    bell: bool = False
    tempdir: str = None
    leave_temps: bool = False
    gen_json: bool = False
    database: str = "/usr/local/share/clamav"
    log: str = None
    recursive: bool = False
    allmatch: bool = False
    cross_fs: YON = "yes"
    follow_dir_symlinks: Literal[1, 2, 3] = 1
    follow_file_symlinks: Literal[1, 2, 3] = 1
    file_list: str = None
    remove: YON = "no"
    move: str = None
    copy: str = (
        None  # TODO: Throwing a warning due to shadowing an attribute from parent
    )
    exclude: str = None
    exclude_dir: str = None
    include: str = None
    include_dir: str = None
    bytecode: YON = "yes"
    bytecode_unsigned: YON = "no"
    bytecode_timeout: int = 10000  # in milliseconds
    statistics: Literal["none", "bytecode", "pcre"] = "none"
    detect_pua: YON = "no"
    exclude_pua: List[PUA_TYPES] = None
    include_pua: List[PUA_TYPES] = None
    detect_structured: YON = "no"
    structured_ssn_format: Literal[0, 1, 2] = 0
    structured_ssn_count: int = 3
    structured_cc_count: int = 3
    scan_mail: YON = "yes"
    phishing_sigs: YON = "yes"
    phishing_scan_urls: YON = "yes"
    heuristic_alerts: YON = "yes"
    heuristic_scan_precedence: YON = "no"
    normalize: YON = "yes"
    scan_pe: YON = "yes"
    scan_elf: YON = "yes"
    scan_ole2: YON = "yes"
    scan_pdf: YON = "yes"
    scan_swf: YON = "yes"
    scan_html: YON = "yes"
    scan_xmldocs: YON = "yes"
    scan_hwp3: YON = "yes"
    scan_onenote: YON = "yes"
    scan_archive: YON = "yes"
    alert_broken: YON = "no"
    alert_broken_media: YON = "no"
    alert_encrypted: YON = "no"
    alert_encrypted_archive: YON = "no"
    alert_encrypted_doc: YON = "no"
    alert_macros: YON = "no"
    alert_exceeds_max: YON = "no"
    alert_phishing_ssl: YON = "no"
    alert_phishing_cloak: YON = "no"
    alert_partition_intersection: YON = "no"
    nocerts: bool = False
    dumpcerts: bool = False
    max_scantime: int = 120000  # 120s or 2min
    max_filesize: int | str = "100M"
    max_scansize: int | str = "400M"
    max_files: int = 10000
    max_recursion: int = 17
    max_dir_recursion: int = 15
    max_embeddedpe: int | str = "40M"
    max_htmlnormalize: int | str = "40M"
    max_htmlnotags: int | str = "8M"
    max_scriptnormalize: int | str = "20M"
    max_ziptypercg: int | str = "1M"
    max_partitions: int = 50
    max_iconspe: int = 100
    max_rechwp3: int = 16
    pcre_match_limit: int = 100000
    pcre_recmatch_limit: int = 2000
    pcre_max_filesize: int = 100000000
    disable_cache: bool = False

    def build_command_list(self) -> List[str]:
        """Builds a list of command arguments based on the set attributes.

        Returns:
            List[str]: A list of command-line arguments for ClamAV.
        """

        command_list = [self.command]
        pure_flags = set(
            [
                "verbose",
                "archive_verbose",
                "allmatch",
                "recursive",
                "debug",
                "quiet",
                "stdout",
                "no_summary",
                "infected",
                "suppress_ok_results",
                "bell",
                "nocerts",
                "dumpcerts",
                "disable_cache",
            ]
        )  # The attributes with no value passed and are purely flags
        for field_name, field_value in self:
            flagged_field_name = f"--{field_name.replace("_", "-")}"
            if field_name == "command":
                continue
            # Handle pure flags
            if field_name in pure_flags and field_value is not False:
                command_list.append(flagged_field_name)
            # Handle everything else
            elif field_name not in pure_flags and (field_value or field_value == 0):
                command_list.append(f"{flagged_field_name}={field_value}")
            # Check if anything was missed
            else:
                guardian_logger.error(
                    f"Field Name: {field_name}    Field Value: {field_value}"
                )

        return command_list
