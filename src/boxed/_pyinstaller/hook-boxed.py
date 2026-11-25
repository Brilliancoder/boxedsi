"""PyInstaller hook for boxed: what a scan of the imports cannot see.

PyInstaller finds it through the pyinstaller40 entry point (pyproject.toml), so that a build of a script that imports boxed needs no
--hidden-import, --collect-submodules or --copy-metadata of its own.
"""

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

# boxed.formats loads these by name with importlib (formats.need) when a file type needs them. They come with the `formats` extra: a
# build made without it gets a warning for each, and the formats say "needs the formats extra" when they run, as they do unfrozen.
hiddenimports = ["openpyxl", "docx", "pypdf"]
# keyring chooses the backend of the system (Credential Manager, Keychain, Secret Service) through entry points when it runs
hiddenimports += collect_submodules("keyring.backends")
datas = copy_metadata("keyring")
