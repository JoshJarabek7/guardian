import pytest
from pydantic import ValidationError

from hiss.options import ScannerOptions
import logging


def test_default_values():
    """Test default values without passing any arguments."""
    options = ScannerOptions()
    assert options.command == "clamscan"
    assert options.verbose is False
    assert options.archive_verbose is False
    assert options.debug is False
    assert options.quiet is False
    assert options.stdout is False
    assert options.no_summary is False
    assert options.infected is False
    assert options.suppress_ok_results is False
    assert options.bell is False
    assert options.tempdir is None
    assert options.leave_temps is False
    assert options.gen_json is False
    assert options.database is None
    assert options.log is None
    assert options.recursive is False
    assert options.allmatch is False
    assert options.cross_fs == "yes"
    assert options.follow_dir_symlinks == 1
    assert options.follow_file_symlinks == 1
    assert options.file_list is None
    assert options.remove == "no"
    assert options.move is None
    assert options.copy_atr is None
    assert options.exclude is None
    assert options.exclude_dir is None
    assert options.include is None
    assert options.include_dir is None
    assert options.bytecode == "yes"
    assert options.bytecode_unsigned == "no"
    assert options.bytecode_timeout == 10000
    assert options.statistics == "none"
    assert options.detect_pua == "no"
    assert options.exclude_pua is None
    assert options.include_pua is None
    assert options.detect_structured == "no"
    assert options.structured_ssn_format == 0
    assert options.structured_ssn_count == 3
    assert options.structured_cc_count == 3
    assert options.scan_mail == "yes"
    assert options.phishing_sigs == "yes"
    assert options.phishing_scan_urls == "yes"
    assert options.heuristic_alerts == "yes"
    assert options.heuristic_scan_precedence == "no"
    assert options.normalize == "yes"
    assert options.scan_pe == "yes"
    assert options.scan_elf == "yes"
    assert options.scan_ole2 == "yes"
    assert options.scan_pdf == "yes"
    assert options.scan_swf == "yes"
    assert options.scan_html == "yes"
    assert options.scan_xmldocs == "yes"
    assert options.scan_hwp3 == "yes"
    assert options.scan_onenote == "yes"
    assert options.scan_archive == "yes"
    assert options.alert_broken == "no"
    assert options.alert_broken_media == "no"
    assert options.alert_encrypted == "no"
    assert options.alert_encrypted_archive == "no"
    assert options.alert_encrypted_doc == "no"
    assert options.alert_macros == "no"
    assert options.alert_exceeds_max == "no"
    assert options.alert_phishing_ssl == "no"
    assert options.alert_phishing_cloak == "no"
    assert options.alert_partition_intersection == "no"
    assert options.nocerts is False
    assert options.dumpcerts is False
    assert options.max_scantime == 120000
    assert options.max_filesize == "100M"
    assert options.max_scansize == "400M"
    assert options.max_files == 10000
    assert options.max_recursion == 17
    assert options.max_dir_recursion == 15
    assert options.max_embeddedpe == "40M"
    assert options.max_htmlnormalize == "40M"
    assert options.max_htmlnotags == "8M"
    assert options.max_scriptnormalize == "20M"
    assert options.max_ziptypercg == "1M"
    assert options.max_partitions == 50
    assert options.max_iconspe == 100
    assert options.max_rechwp3 == 16
    assert options.pcre_match_limit == 100000
    assert options.pcre_recmatch_limit == 2000
    assert options.pcre_max_filesize == 100000000
    assert options.disable_cache is False


def test_custom_values():
    """Test custom values being passed as arguments."""
    options = ScannerOptions(
        command="customscan",
        verbose=True,
        archive_verbose=True,
        debug=True,
        quiet=True,
        stdout=True,
        no_summary=True,
        infected=True,
        suppress_ok_results=True,
        bell=True,
        tempdir="/tmp",
        leave_temps=True,
        gen_json=True,
        database="/custom/path",
        log="/custom/log",
        recursive=True,
        allmatch=True,
        cross_fs="no",
        follow_dir_symlinks=2,
        follow_file_symlinks=2,
        file_list="/custom/list",
        remove="yes",
        move="/custom/move",
        copy_atr="/custom/copy",
        exclude="exclude",
        exclude_dir="exclude_dir",
        include="include",
        include_dir="include_dir",
        bytecode="no",
        bytecode_unsigned="yes",
        bytecode_timeout=5000,
        statistics="bytecode",
        detect_pua="yes",
        exclude_pua=["Andr.Adware"],
        include_pua=["Andr.Tool"],
        detect_structured="yes",
        structured_ssn_format=1,
        structured_ssn_count=5,
        structured_cc_count=5,
        scan_mail="no",
        phishing_sigs="no",
        phishing_scan_urls="no",
        heuristic_alerts="no",
        heuristic_scan_precedence="yes",
        normalize="no",
        scan_pe="no",
        scan_elf="no",
        scan_ole2="no",
        scan_pdf="no",
        scan_swf="no",
        scan_html="no",
        scan_xmldocs="no",
        scan_hwp3="no",
        scan_onenote="no",
        scan_archive="no",
        alert_broken="yes",
        alert_broken_media="yes",
        alert_encrypted="yes",
        alert_encrypted_archive="yes",
        alert_encrypted_doc="yes",
        alert_macros="yes",
        alert_exceeds_max="yes",
        alert_phishing_ssl="yes",
        alert_phishing_cloak="yes",
        alert_partition_intersection="yes",
        nocerts=True,
        dumpcerts=True,
        max_scantime=60000,
        max_filesize="50M",
        max_scansize="200M",
        max_files=5000,
        max_recursion=10,
        max_dir_recursion=5,
        max_embeddedpe="20M",
        max_htmlnormalize="20M",
        max_htmlnotags="4M",
        max_scriptnormalize="10M",
        max_ziptypercg="500K",
        max_partitions=25,
        max_iconspe=50,
        max_rechwp3=8,
        pcre_match_limit=50000,
        pcre_recmatch_limit=1000,
        pcre_max_filesize=50000000,
        disable_cache=True,
    )
    assert options.command == "customscan"
    assert options.verbose is True
    assert options.archive_verbose is True
    assert options.debug is True
    assert options.quiet is True
    assert options.stdout is True
    assert options.no_summary is True
    assert options.infected is True
    assert options.suppress_ok_results is True
    assert options.bell is True
    assert options.tempdir == "/tmp"
    assert options.leave_temps is True
    assert options.gen_json is True
    assert options.database == "/custom/path"
    assert options.log == "/custom/log"
    assert options.recursive is True
    assert options.allmatch is True
    assert options.cross_fs == "no"
    assert options.follow_dir_symlinks == 2
    assert options.follow_file_symlinks == 2
    assert options.file_list == "/custom/list"
    assert options.remove == "yes"
    assert options.move == "/custom/move"
    assert options.copy_atr == "/custom/copy"
    assert options.exclude == "exclude"
    assert options.exclude_dir == "exclude_dir"
    assert options.include == "include"
    assert options.include_dir == "include_dir"
    assert options.bytecode == "no"
    assert options.bytecode_unsigned == "yes"
    assert options.bytecode_timeout == 5000
    assert options.statistics == "bytecode"
    assert options.detect_pua == "yes"
    assert options.exclude_pua == ["Andr.Adware"]
    assert options.include_pua == ["Andr.Tool"]
    assert options.detect_structured == "yes"
    assert options.structured_ssn_format == 1
    assert options.structured_ssn_count == 5
    assert options.structured_cc_count == 5
    assert options.scan_mail == "no"
    assert options.phishing_sigs == "no"
    assert options.phishing_scan_urls == "no"
    assert options.heuristic_alerts == "no"
    assert options.heuristic_scan_precedence == "yes"
    assert options.normalize == "no"
    assert options.scan_pe == "no"
    assert options.scan_elf == "no"
    assert options.scan_ole2 == "no"
    assert options.scan_pdf == "no"
    assert options.scan_swf == "no"
    assert options.scan_html == "no"
    assert options.scan_xmldocs == "no"
    assert options.scan_hwp3 == "no"
    assert options.scan_onenote == "no"
    assert options.scan_archive == "no"
    assert options.alert_broken == "yes"
    assert options.alert_broken_media == "yes"
    assert options.alert_encrypted == "yes"
    assert options.alert_encrypted_archive == "yes"
    assert options.alert_encrypted_doc == "yes"
    assert options.alert_macros == "yes"
    assert options.alert_exceeds_max == "yes"
    assert options.alert_phishing_ssl == "yes"
    assert options.alert_phishing_cloak == "yes"
    assert options.alert_partition_intersection == "yes"
    assert options.nocerts is True
    assert options.dumpcerts is True
    assert options.max_scantime == 60000
    assert options.max_filesize == "50M"
    assert options.max_scansize == "200M"
    assert options.max_files == 5000
    assert options.max_recursion == 10
    assert options.max_dir_recursion == 5
    assert options.max_embeddedpe == "20M"
    assert options.max_htmlnormalize == "20M"
    assert options.max_htmlnotags == "4M"
    assert options.max_scriptnormalize == "10M"
    assert options.max_ziptypercg == "500K"
    assert options.max_partitions == 25
    assert options.max_iconspe == 50
    assert options.max_rechwp3 == 8
    assert options.pcre_match_limit == 50000
    assert options.pcre_recmatch_limit == 1000
    assert options.pcre_max_filesize == 50000000
    assert options.disable_cache is True


def test_invalid_values():  # pyright: ignore
    """Test invalid value types being passed as arguments."""
    with pytest.raises(ValidationError):  # pyright: ignore
        ScannerOptions(follow_dir_symlinks=4)  # pyright: ignore
    with pytest.raises(ValidationError):  # noqa: E501
        ScannerOptions(detect_structured="maybe")  # pyright: ignore
    with pytest.raises(ValidationError):  # pyright: ignore
        ScannerOptions(exclude_pua=["Invalid.PUA"])  # pyright: ignore


def test_build_command_list():
    """Test the command list being built."""
    options = ScannerOptions(
        verbose=True,
        archive_verbose=True,
        debug=True,
        quiet=True,
        stdout=True,
        no_summary=True,
        infected=True,
        suppress_ok_results=True,
        bell=True,
        tempdir="/tmp",
        leave_temps=True,
        gen_json=True,
        database=None,
        log="/custom/log",
        recursive=True,
        allmatch=True,
        cross_fs="no",
        follow_dir_symlinks=2,
        follow_file_symlinks=2,
        file_list="/custom/list",
        remove="yes",
        move="/custom/move",
        copy_atr="/custom/copy",
        exclude="exclude",
        exclude_dir="exclude_dir",
        include="include",
        include_dir="include_dir",
        bytecode="no",
        bytecode_unsigned="yes",
        bytecode_timeout=5000,
        statistics="bytecode",
        detect_pua="yes",
        exclude_pua=["Andr.Adware"],
        include_pua=["Andr.Tool"],
        detect_structured="yes",
        structured_ssn_format=1,
        structured_ssn_count=5,
        structured_cc_count=5,
        scan_mail="no",
        phishing_sigs="no",
        phishing_scan_urls="no",
        heuristic_alerts="no",
        heuristic_scan_precedence="yes",
        normalize="no",
        scan_pe="no",
        scan_elf="no",
        scan_ole2="no",
        scan_pdf="no",
        scan_swf="no",
        scan_html="no",
        scan_xmldocs="no",
        scan_hwp3="no",
        scan_onenote="no",
        scan_archive="no",
        alert_broken="yes",
        alert_broken_media="yes",
        alert_encrypted="yes",
        alert_encrypted_archive="yes",
        alert_encrypted_doc="yes",
        alert_macros="yes",
        alert_exceeds_max="yes",
        alert_phishing_ssl="yes",
        alert_phishing_cloak="yes",
        alert_partition_intersection="yes",
        nocerts=True,
        dumpcerts=True,
        max_scantime=60000,
        max_filesize="50M",
        max_scansize="200M",
        max_files=5000,
        max_recursion=10,
        max_dir_recursion=5,
        max_embeddedpe="20M",
        max_htmlnormalize="20M",
        max_htmlnotags="4M",
        max_scriptnormalize="10M",
        max_ziptypercg="500K",
        max_partitions=25,
        max_iconspe=50,
        max_rechwp3=8,
        pcre_match_limit=50000,
        pcre_recmatch_limit=1000,
        pcre_max_filesize=50000000,
        disable_cache=True,
    )
    virus_db = options.get_virus_db_directory()
    expected_command = [
        "clamscan",
        "--verbose",
        "--archive-verbose",
        "--debug",
        "--quiet",
        "--stdout",
        "--no-summary",
        "--infected",
        "--suppress-ok-results",
        "--bell",
        "--tempdir=/tmp",
        "--leave-temps",
        "--gen-json",
        f"--database={virus_db}",
        "--log=/custom/log",
        "--recursive",
        "--allmatch",
        "--cross-fs=no",
        "--follow-dir-symlinks=2",
        "--follow-file-symlinks=2",
        "--file-list=/custom/list",
        "--remove=yes",
        "--move=/custom/move",
        "--copy=/custom/copy",
        "--exclude=exclude",
        "--exclude-dir=exclude_dir",
        "--include=include",
        "--include-dir=include_dir",
        "--bytecode=no",
        "--bytecode-unsigned=yes",
        "--bytecode-timeout=5000",
        "--statistics=bytecode",
        "--detect-pua=yes",
        "--exclude-pua=Andr.Adware",
        "--include-pua=Andr.Tool",
        "--detect-structured=yes",
        "--structured-ssn-format=1",
        "--structured-ssn-count=5",
        "--structured-cc-count=5",
        "--scan-mail=no",
        "--phishing-sigs=no",
        "--phishing-scan-urls=no",
        "--heuristic-alerts=no",
        "--heuristic-scan-precedence=yes",
        "--normalize=no",
        "--scan-pe=no",
        "--scan-elf=no",
        "--scan-ole2=no",
        "--scan-pdf=no",
        "--scan-swf=no",
        "--scan-html=no",
        "--scan-xmldocs=no",
        "--scan-hwp3=no",
        "--scan-onenote=no",
        "--scan-archive=no",
        "--alert-broken=yes",
        "--alert-broken-media=yes",
        "--alert-encrypted=yes",
        "--alert-encrypted-archive=yes",
        "--alert-encrypted-doc=yes",
        "--alert-macros=yes",
        "--alert-exceeds-max=yes",
        "--alert-phishing-ssl=yes",
        "--alert-phishing-cloak=yes",
        "--alert-partition-intersection=yes",
        "--nocerts",
        "--dumpcerts",
        "--max-scantime=60000",
        "--max-filesize=50M",
        "--max-scansize=200M",
        "--max-files=5000",
        "--max-recursion=10",
        "--max-dir-recursion=5",
        "--max-embeddedpe=20M",
        "--max-htmlnormalize=20M",
        "--max-htmlnotags=4M",
        "--max-scriptnormalize=10M",
        "--max-ziptypercg=500K",
        "--max-partitions=25",
        "--max-iconspe=50",
        "--max-rechwp3=8",
        "--pcre-match-limit=50000",
        "--pcre-recmatch-limit=1000",
        "--pcre-max-filesize=50000000",
        "--disable-cache",
    ]
    command_list = options.build_command_list()
    real_options_set = set(command_list)
    expected_command_set = set(expected_command)
    assert command_list == expected_command
    assert real_options_set == expected_command_set
    assert len(real_options_set) == len(expected_command_set)


def test_get_virus_db_directory(caplog):
    caplog.set_level(logging.INFO)
    options = ScannerOptions()
    db_directory = options.get_virus_db_directory()
    assert db_directory


if __name__ == "__main__":
    pytest.main()
