# -*- coding: utf-8 -*-

'''''''''''''''''''''''''''''''''
@Author : Vic P.
@Email  : vic4key@gmail.com
@Name   : Dependency Walker
'''''''''''''''''''''''''''''''''

import sys, argparse
from PyVutils import Others
from DependencyWalker import *

__package__ = "Dependency Walker"
__version__ = "1.0.0"

ACTIONS = ["walker", "fulfil"]

def printout(args, dependencies: dict, key: str):
  # Print the result
  fulfil = args.action == "fulfil"
  resolvable = fulfil and key == "resolvable"

  m = {
    "resolvable": ("Resolved:" if fulfil else "Resolvable:", "+"),
    "unresolvable": ("Unresolvable:", "?")
  }
  print(m[key][0])

  items = dependencies[key].items()
  if len(items) == 0:
    print("   No any dependency")
    return

  target_dir, _ = os.path.split(args.target)

  for file_name, file_path in items:
    s = f"   {m[key][1]} `{file_name}`"
    if resolvable:
      s += f" [{file_path}]"
      shutil.copy(file_path, os.path.join(target_dir, file_name))
    print(s)

  return

def main():
  print(f"{__package__} {__version__}")

  parser = argparse.ArgumentParser(description=__package__)
  parser.add_argument("-a", "--action", type=str, required=True, default="", choices=ACTIONS, help="The action to do")
  parser.add_argument("-t", "--target", type=str, required=True, default="", help="The target file that a pe-file")
  parser.add_argument("-d", "--dirs", type=str, required=True, nargs="+", help="Set of directories that contains dependency files")
  parser.add_argument("-e", "--exts", type=str, default=[], nargs="+", help="Set of extensions or any as default")
  parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Print the verbose information")
  args = parser.parse_args()

  print(f"Target: `{args.target}`")

  print(f"Dirs:")
  for dir in args.dirs: print(f"   + `{dir}`")

  print(f"Exts:")
  print(f"   + `{'*.*' if not args.exts else ' '.join(args.exts)}`")

  if args.action in ACTIONS:
    dw = DependencyWalker(args.target, args.dirs, args.exts, args.verbose)
    dependencies = dw.walk()
    if dependencies:
      printout(args, dependencies, "resolvable")
      printout(args, dependencies, "unresolvable")
    else:
      print("Error:")
      print("   The provided target is not found")
  else: print("Action is not available")

  print("Finish!")

  return 0

if __name__ == "__main__":
  try: sys.exit(main())
  except (Exception, KeyboardInterrupt): Others.LogException(sys.exc_info())
