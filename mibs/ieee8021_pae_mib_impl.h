/**
 * @file ieee8021_pae_mib_impl.h
 * @brief Port Access Control MIB module implementation
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

#ifndef _IEEE8021_PAE_MIB_IMPL_H
#define _IEEE8021_PAE_MIB_IMPL_H

//Dependencies
#include "mibs/mib_common.h"
#include "eap/eap.h"
#include "authenticator/authenticator.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Port Access Control MIB related functions
error_t ieee8021PaeMibInit(void);
void ieee8021PaeMibLock(void);
void ieee8021PaeMibUnlock(void);

error_t ieee8021PaeMibSetAuthenticatorContext(AuthenticatorContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
