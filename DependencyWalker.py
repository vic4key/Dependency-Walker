import os, pefile, ctypes, pprint, shutil, json, time
from PyVutils import File

class DependencyWalker:
  # Dependency Walker

  g_list_checked_files = set()

  def __init__(self, target: str, dirs: list, exts: list, verbose: bool):
    # Constructor
    self.m_verbose = verbose
    self.m_print = pprint.PrettyPrinter(indent=2)

    self.m_pe_target = target
    if not File.IsFileExists(self.m_pe_target): return
    target_dir, _ = os.path.split(self.m_pe_target)
    target_dir = self._normalize_dirs([target_dir])[0]

    self.m_dependency_exts = exts

    self.m_pe_dependency_dirs  = self._normalize_dirs(dirs)
    self.m_pe_dependency_files = self.walk_dependency_dirs(self.m_pe_dependency_dirs)

    self.m_dependency_file_exists = self.walk_dependency_dir(target_dir)
    self.m_pe_dependency_files.update({target_dir: self.m_dependency_file_exists})
    self._log(self.m_pe_dependency_files)

    self.m_pe_target_dependencies = set()

    self.m_prefs = self._load_prefs()
    self.m_list_ignore_prefix = self.m_prefs.get("ignore_prefix", [])
    # self._log(self.m_list_ignore_prefix)

  def _log(self, *args):
    # Logging message
    if self.m_verbose and len(*args) != 0: self.m_print.pprint(*args)
    return

  def _normalize_dirs(self, dirs: list):
    # Normalize all directories
    result = []
    for dir in dirs: result.append(File.NormalizePath(dir, True))
    return result

  def _load_prefs(self):
    # Load preferences from a json file
    result = {}
    try:
      PREFS_FILE_NAME = R"prefs.json"
      if File.IsFileExists(PREFS_FILE_NAME):
          data = File.Read(PREFS_FILE_NAME)
          if data: result = json.loads(data)
    except Exception as e:
      result = {}
      self._log("prefs failed", e)
    return result

  def _is_file_checked(self, file_path: str):
    # Determine that a file is checked or not
    s = file_path.lower()
    if s in DependencyWalker.g_list_checked_files: return True
    DependencyWalker.g_list_checked_files.add(s)
    # self._log(file_path)
    return False

  def walk_dependency_dirs(self, dirs: list):
    # Walk directories to list dependency files
    DependencyWalker.g_list_checked_files.clear()
    result = {}
    for dir in dirs:
      l = self.walk_dependency_dir(dir)
      if l: result[dir] = l
    return result

  def is_dependency_file(self, file_path: str):
    # Determine that a file is a dependency file or not
    start_time = time.perf_counter()

    if self._is_file_checked(file_path):
      return False

    with open(file_path, "rb") as file:
      if file.read(2) != b"MZ": return False

    pe = pefile.PE(file_path, fast_load=True)
    # IMAGE_DIRECTORY_ENTRY_EXPORT/IMPORT
    pe.parse_data_directories([0, 1], True, True) # IMAGE_DIRECTORY_ENTRY_EXPORT/IMPORT

    delta_time = time.perf_counter() - start_time
    self._log(f"{File.ExtractFileName(file_path)} -> {delta_time:.3f}s")

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"): return False

    return True

  def walk_dependency_dir(self, dir: str):
    # Walk a single directory to list dependency files
    result = []

    len_dir = len(dir)
    assert len_dir != 0

    def fn_callback(file_path, file_dir, file_name):
      if self.is_dependency_file(file_path): result.append(os.path.split(file_path))
      return

    File.LSRecursive(dir, fn_callback, self.m_dependency_exts)

    return result

  def _walk_dependency_file(self, file_path: str):
    # Walk a single file
    start_time = time.perf_counter()

    if not File.IsFileExists(file_path): return []
    if self._is_file_checked(file_path): return []

    pe = pefile.PE(file_path, fast_load=True)
    pe.parse_data_directories([0, 1], True, True) # IMAGE_DIRECTORY_ENTRY_EXPORT/IMPORT

    delta_time = time.perf_counter() - start_time
    self._log(f"{File.ExtractFileName(file_path)} -> {delta_time:.3f}s")

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"): return []

    result = set()
    for idi in pe.DIRECTORY_ENTRY_IMPORT:
      dependency_file_name = idi.dll.decode("utf-8")
      if not dependency_file_name.lower().startswith(tuple(self.m_list_ignore_prefix)):
        result.add(dependency_file_name)

    return result
    # return set(map(lambda idi: idi.dll.decode("utf-8"), pe.DIRECTORY_ENTRY_IMPORT))

  def _get_nonsys_dependency_files(self, dependency_files: set):
    # Get non-system dependency files
    result = set()
    for dependency_file in dependency_files:
      module = None
      try: module = ctypes.cdll.LoadLibrary(dependency_file)
      except: pass
      finally:
        if module: del module # ctypes.windll.kernel32.FreeLibrary(module)
        else: result.add(dependency_file)
    return result

  def _get_file_path_by_file_name(self, dependency_file_name: str):
    # Get dependency file path by file name
    result = ""
    for _, files in self.m_pe_dependency_files.items():
      for file in files:
        file_dir, file_name = file
        if dependency_file_name.lower() == file_name.lower():
          result = os.path.join(file_dir, file_name)
          break
    return result

  def _walk_recursive_dependency_files(self, dependency_files: set):
    # Recursive walking dependency files and their dependencies
    result = dependency_files.copy()

    for dependency_file in dependency_files:
      file_path = self._get_file_path_by_file_name(dependency_file)
      dependencies = self._walk_dependency_file(file_path)
      dependencies = self._get_nonsys_dependency_files(dependencies)
      if dependencies:
        dependencies = self._walk_recursive_dependency_files(dependencies)
        result.update(dependencies)
      else: continue

    return result

  def _remove_exist_dependency_files(self, dependency_files: set):
    # Remove dependencies that exists in the target directory
    result = dependency_files.copy()

    if self.m_dependency_file_exists:
      _, dependency_file_exists = list(zip(*self.m_dependency_file_exists))
      result -= set(dependency_file_exists)

    return result

  def walk(self):
    # Walk all dependencies in the target
    if not File.IsFileExists(self.m_pe_target): return None

    DependencyWalker.g_list_checked_files.clear()

    self.m_pe_target_dependencies =\
      self._walk_dependency_file(self.m_pe_target)
    self._log(self.m_pe_target_dependencies)

    self.m_pe_target_dependencies =\
      self._get_nonsys_dependency_files(self.m_pe_target_dependencies)
    self._log(self.m_pe_target_dependencies)

    self.m_pe_target_dependencies =\
      self._walk_recursive_dependency_files(self.m_pe_target_dependencies)
    self._log(self.m_pe_target_dependencies)

    self.m_pe_target_dependencies =\
      self._remove_exist_dependency_files(self.m_pe_target_dependencies)
    self._log(self.m_pe_target_dependencies)

    result = {"resolvable": {}, "unresolvable": {}}
    for dependency in self.m_pe_target_dependencies:
      file_path = self._get_file_path_by_file_name(dependency)
      key = "resolvable" if File.IsFileExists(file_path) else "unresolvable"
      result[key].update({dependency: file_path})

    return result
