"""Install the WebEngine candidate built for the Qt 6.12 SDK."""

import os
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from aqt.archives import ModuleToPackage, QtArchives, TargetConfig, UpdateXmls
from aqt.helper import Settings
from aqt.installer import run_installer
from aqt.metadata import QtRepoProperty, Version
from aqt.updater import Updater


QT_VERSION = '6.12.0'
WEBENGINE_BUILD = '6.12.0-0-202609281005'


class WebEngineArchives(QtArchives):
    def _get_archives(self):
        host = self._resolve_os_segment()
        arch = self._compute_extension_arch(host)
        repository = f'online/qtsdkrepository/{host}/extensions/qtwebengine/6120/61400/{arch}'
        package = f'extensions.qtwebengine.6120.61400.{self.arch}'
        metadata = self._download_update_xml(f'{repository}/Updates.xml')
        self._parse_update_xmls([UpdateXmls(repository, metadata)],
                               ModuleToPackage({'qtwebengine': [package]}))


def install(sdk, host, arch):
    if not sdk.is_absolute() or not (sdk / 'bin').is_dir():
        raise RuntimeError(f'Invalid Qt installation directory: {sdk}')
    Settings.load_settings()
    archives = WebEngineArchives(host, 'desktop', QT_VERSION, arch,
                                 'https://download.qt.io', modules=['qtwebengine'],
                                 is_include_base_package=False, timeout=(30, 30))
    packages = [p for p in archives.get_packages() if p.name == 'qtwebengine']
    if len(packages) != 1 or WEBENGINE_BUILD not in packages[0].archive_path:
        raise RuntimeError('WebEngine build changed; review the candidate before updating the SDK')

    with TemporaryDirectory(prefix='justconnect-webengine-') as directory:
        temporary = Path(directory)
        run_installer(packages, str(temporary), None, False, temporary)
        webengine = temporary / QT_VERSION / QtRepoProperty.get_arch_dir_name(host, arch, Version(QT_VERSION))
        for link in webengine.rglob('*'):
            destination = sdk / link.relative_to(webengine)
            if link.is_symlink() and destination.is_symlink():
                destination.unlink()
        shutil.copytree(webengine, sdk, dirs_exist_ok=True, symlinks=True)

    Updater.update(TargetConfig(QT_VERSION, 'desktop', arch, host), sdk.parents[1], None)
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(0x8003)
        with os.add_dll_directory(str(sdk / 'bin')):
            ctypes.WinDLL(str(sdk / 'bin' / 'Qt6WebEngineWidgets.dll'))


if __name__ == '__main__':
    install(Path(os.environ['QT_ROOT_DIR']), os.environ['QT_INSTALL_HOST'], os.environ['QT_INSTALL_ARCH'])
