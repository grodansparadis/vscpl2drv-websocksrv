## Install the driver on Linux
You can install the driver using the debian package with

> sudo apt install ./vscpl2drv-websocksrv.y.z.deb

the driver will be installed to /var/lib/vscp/drivers/level2

If you want to use the driver with the [VSCP Daemon](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_daemon) you need to add it to the vscpd.json file (/etc/vscp/vscpd.json). Se [this document](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon) on how to do this.

For [VSCP Works](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_works) you need to add the driver in the VSCP Works configuration dialog [Add connection](https://grodansparadis.github.io/vscp-works-qt/#/connections).

For other applications check the documentation for that application on how to add VSCP level II drivers.

You also need to set up a configuration file for the driver itself. If you don't need to dynamically edit the content of this file a good and safe location for it is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration a good place to put the file is in the */var/vscp/lib/vscp/vscpd/* folder or maybe a subfolder here. Make sure the _vscp_ user can read/write the location.

A sample configuration file is make available in */usr/share/vscpl2drv-websocksrv.so* after installation.

## Install the driver on Windows

Download the Windows package from the project's
[GitHub Releases](https://github.com/grodansparadis/vscpl2drv-websocksrv/releases)
page. Depending on the release, packages may include an NSIS installer (`.exe`)
and a portable ZIP archive.

- Run the installer and follow its prompts, or extract the ZIP to a folder
  accessible to the VSCP host application.
- Keep the driver DLL and its runtime dependency DLLs together in the installed
  folder, or ensure those dependencies are available on `PATH`.
- Create a driver configuration JSON file and a separate user JSON file. See
  [Configure the driver](./configure.md) for the formats and required paths.
- Add a Level II driver entry to the VSCP daemon or other host application,
  pointing `path-driver` to the installed driver DLL and `path-config` to the
  driver configuration file. See the host application's documentation for
  registration details.

If no Windows binary package is available for your release, build the driver
from source using the [Windows build instructions](./build.md#build-from-source-on-windows).

## Install the driver on MacOS

Download the macOS package from the project's
[GitHub Releases](https://github.com/grodansparadis/vscpl2drv-websocksrv/releases)
page, if one is published for your macOS version and CPU architecture. Releases
may provide a disk image (`.dmg`) or a compressed archive (`.tgz`).

Open the disk image or extract the archive, then copy the driver library
(`.dylib`) to a directory readable by the VSCP host application. If the release
does not include a macOS package, build the library using the
[macOS build instructions](./build.md#build-driver-from-source-on-macos).

The driver depends on Expat, OpenSSL, and libsodium. If these libraries are not
bundled with the release, install compatible runtime libraries for your
architecture (for example, with Homebrew) and ensure the host process can find
them.

Create a driver configuration file and a separate user JSON file, then
configure your VSCP host application to load the `.dylib` and pass the driver
configuration path. See [Configure the driver](./configure.md) and the host
application's documentation. Preserve the package's directory layout if it
contains runtime dependencies or sample files.

[filename](./bottom-copyright.md ':include')