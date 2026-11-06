## Build from source on Linux

```bash
git clone --recurse-submodules -j4 https://github.com/grodansparadis/vscpl2drv-websocksrv.git
sudo apt install pandoc           (comment: *optional*)
sudo apt install build-essential
sudo apt install cmake
sudo apt install libexpat-dev
sudo apt install libssl-dev
sudo apt install libsodium-dev
sudo apt install rpm (comment: only if you want to create rpm install packages)
cd vscpl2drv-websocksrv
mkdir build
cd build
cmake ..
make
sudo make install
cpack .. (comment: only if you want to create install packages)
```

Install of _pandoc_ is only needed if man pages should be rebuilt. This is normally already done and available in the repository.

`make install` will install the driver to the standard location for VSCP level II drivers on Linux which is */usr/local/lib/vscp/drivers/* and copy a sample configuration file to */etc/vscp*

## Build from source on Windows

### Prerequisites

Install Visual Studio 2022 with the **Desktop development with C++** workload,
including the Windows SDK, and install Git and CMake. Use a Visual Studio
Developer PowerShell or x64 Native Tools command prompt for the commands below.

Pandoc is optional and is only needed when regenerating manual pages. NSIS is
optional and is only needed to create an installer.

### Install dependencies with vcpkg

Clone and bootstrap vcpkg:

```powershell
git clone https://github.com/microsoft/vcpkg.git C:\src\vcpkg
cd C:\src\vcpkg
.\bootstrap-vcpkg.bat
```

Install the libraries required by the driver:

```powershell
.\vcpkg.exe install expat:x64-windows openssl:x64-windows pthreads:x64-windows dlfcn-win32:x64-windows libsodium:x64-windows
```

See Microsoft's documentation for [vcpkg](https://learn.microsoft.com/en-us/vcpkg/)
and [CMake integration](https://learn.microsoft.com/en-us/vcpkg/users/buildsystems/cmake-integration).

### Configure and build

Clone the source and configure CMake with the vcpkg toolchain. Adjust the
toolchain path if vcpkg is installed elsewhere:

```powershell
git clone https://github.com/grodansparadis/vscpl2drv-websocksrv.git
cd vscpl2drv-websocksrv
cmake -S . -B build `
  -DCMAKE_TOOLCHAIN_FILE=C:/src/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows `
  -A x64
cmake --build build --config Release --parallel
```

Use `--config Debug` to build a debug configuration. With the Visual Studio
generator, the build configuration is selected at build time (not with
`CMAKE_BUILD_TYPE`). The DLL and test app are placed in the configuration's
build output directories.

### Create Windows packages

Run CPack from the build directory. ZIP archives can be generated without
NSIS; install NSIS to create an executable installer:

```powershell
cd build
cpack -G ZIP .
cpack -G NSIS .
```

## Build driver from source on MacOS

### Prerequisites

Install Apple's Xcode Command Line Tools and Homebrew, then install CMake and
the required libraries:

```bash
xcode-select --install
brew install cmake expat libsodium openssl
```

Pandoc is optional and is only needed when regenerating manual pages.

### Configure and build

Clone the repository and configure it with Homebrew's OpenSSL location. CMake
fetches the VSCP, Mongoose, spdlog, and nlohmann JSON sources as part of the
configure step, so a recursive submodule checkout is not required.

```bash
git clone https://github.com/grodansparadis/vscpl2drv-websocksrv.git
cd vscpl2drv-websocksrv
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl)" \
  -DCMAKE_PREFIX_PATH="$(brew --prefix)"
cmake --build build --config Release --parallel
```

The driver library and test app are written to the `build` directory. To
produce the available macOS packages:

```bash
cd build
cpack -G TGZ .
cpack -G DragNDrop .
```

If installing the library manually, copy the resulting `.dylib` to the
directory used by your VSCP host for Level II drivers. Configure the host with
the full library path and the driver configuration path. See
[Install the driver on MacOS](./install.md#install-the-driver-on-macos) and
[Configure the driver](./configure.md).

[filename](./bottom-copyright.md ':include')