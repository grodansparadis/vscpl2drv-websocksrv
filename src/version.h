// version.h
//
// Copyright (C) 2000-2026 Ake Hedman, the VSCP project
// <info@vscp.org>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-2.0-only
#ifndef _____VSCPL2DRV_WEBSOCKSRV_VERSION_h_____
#define _____VSCPL2DRV_WEBSOCKSRV_VERSION_h_____
/*
    YEAR is the release year,
    MONTH is the release month,
    PATCH is the patch number.
*/
#define VSCPL2DRV_WEBSOCKSRV_MAJOR_VERSION     2026
#define VSCPL2DRV_WEBSOCKSRV_MINOR_VERSION     11
#define VSCPL2DRV_WEBSOCKSRV_PATCH_VERSION   15

#define VSCPL2DRV_WEBSOCKSRV_DISPLAY_VERSION   "2026.11.15"

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
