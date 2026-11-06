// version.h
//
// The MIT License (MIT)
//
// Copyright (C) 2000-2026 Ake Hedman, the VSCP project
// <info@vscp.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#ifndef _____VSCPL2DRV_WEBSOCKSRV_VERSION_h_____
#define _____VSCPL2DRV_WEBSOCKSRV_VERSION_h_____
/*
    YEAR is the release year,
    MONTH is the release month,
    PATCH is the patch number.
*/
#define VSCPL2DRV_WEBSOCKSRV_MAJOR_VERSION     2026
#define VSCPL2DRV_WEBSOCKSRV_MINOR_VERSION     11
#define VSCPL2DRV_WEBSOCKSRV_PATCH_VERSION   11

#define VSCPL2DRV_WEBSOCKSRV_DISPLAY_VERSION   "2026.11.11"

#define VSCPL2DRV_WEBSOCKSRV_COPYRIGHT                                      \
    "Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP project, "                \
    "https://www.vscp.org"
#define VSCPL2DRV_WEBSOCKSRV_COPYRIGHT_HTML                                 \
    "Copyright (C) 2000-2026 Ake Hedman and contributors, <a "                               \
    "href=\"mailto:info@vscp.org\">the VSCP project</a>, <a "               \
    "href=\"https://www.vscp.org\">https://"                                \
    "www.vscp.org</a>"

#define MAKE_VSCPL2DRV_WEBSOCKSRV_VERSION(major, minor, release)            \
    (((major) << 16) | ((minor) << 8) | (release))
#endif
