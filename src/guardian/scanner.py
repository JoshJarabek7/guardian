"""Contains the ClamAVScanner class, which handles the actual scanning and database update functionality"""

import asyncio


class ClamAVScanner:
    def __init__(self, command, database_path, file_path, in_memory, verbose, archive_verbose,
                 debug, quiet, stdout, no_summary, infected, suppress_ok_results, bell,
                 tempdir, leave_temps, gen_json, recursive, allmatch, cross_fs,
                 follow_dir_symlinks, follow_file_symlinks, file_list, remove, move,
                 copy, exclude, exclude_dir, include, include_dir):
        self.command = command
        self.database_path = database_path
        self.file_path = file_path
        self.in_memory = in_memory
        self.verbose = verbose
        self.archive_verbose = archive_verbose
        self.debug = debug
        self.quiet = quiet
        self.stdout = stdout
        self.no_summary = no_summary
        self.infected = infected
        self.suppress_ok_results = suppress_ok_results
        self.bell = bell
        self.tempdir = tempdir
        self.leave_temps = leave_temps
        self.gen_json = gen_json
        self.recursive = recursive
        self.allmatch = allmatch
        self.cross_fs = cross_fs
        self.follow_dir_symlinks = follow_dir_symlinks
        self.follow_file_symlinks = follow_file_symlinks
        self.file_list = file_list
        self.remove = remove
        self.move = move
        self.copy = copy
        self.exclude = exclude
        self.exclude_dir = exclude_dir
        self.include = include
        self.include_dir = include_dir

    async def scan_file(self, file_path):
        command = [self.command]
        command.extend(["--database", self.database_path])

        if self.verbose:
            command.append("-v")
        if self.archive_verbose:
            command.append("-a")
        if self.debug:
            command.append("--debug")
        if self.quiet:
            command.append("--quiet")
        if self.stdout:
            command.append("--stdout")
        if self.no_summary:
            command.append("--no-summary")
        if self.infected:
            command.append("-i")
        if self.suppress_ok_results:
            command.append("-o")
        if self.bell:
            command.append("--bell")
        if self.tempdir:
            command.extend(["--tempdir", self.tempdir])
        if self.leave_temps:
            command.append("--leave-temps")
        if self.gen_json:
            command.append("--gen-json")
        if self.recursive:
            command.append("-r")
        if self.allmatch:
            command.append("-z")
        if not self.cross_fs:
            command.append("--cross-fs=no")
        if self.follow_dir_symlinks != 1:
            command.extend(["--follow-dir-symlinks", str(self.follow_dir_symlinks)])
        if self.follow_file_symlinks != 1:
            command.extend(["--follow-file-symlinks", str(self.follow_file_symlinks)])
        if self.file_list:
            command.extend(["-f", self.file_list])
        if self.remove:
            command.append("--remove")
        if self.move:
            command.extend(["--move", self.move])
        if self.copy:
            command.extend(["--copy", self.copy])
        if self.exclude:
            command.extend(["--exclude", self.exclude])
        if self.exclude_dir:
            command.extend(["--exclude-dir", self.exclude_dir])
        if self.include:
            command.extend(["--include", self.include])
        if self.include_dir:
            command.extend(["--include-dir", self.include_dir])

        command.append(file_path)

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            return True
        else:
            return False

    async def update_database(self):
        command = f"{self.command} --database={self.database_path} --update"
        process = await asyncio.create_subprocess_exec(
            *command.split(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()