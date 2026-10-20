/**
 * @file eap_md5.h
 * @brief MD5-Challenge authentication method
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneEAP Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.8
 **/

#ifndef _EAP_MD5_H
#define _EAP_MD5_H

//Dependencies
#include "eap/eap.h"
#include "supplicant/supplicant.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EAP-MD5 related functions
error_t eapMd5CheckRequest(SupplicantContext *context,
   const EapMd5Packet *request, size_t length);

void eapMd5ProcessRequest(SupplicantContext *context,
   const EapMd5Packet *request, size_t length);

void eapMd5BuildResponse(SupplicantContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
