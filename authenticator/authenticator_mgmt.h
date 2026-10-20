/**
 * @file authenticator_mgmt.h
 * @brief Management of the 802.1X authenticator
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

#ifndef _AUTHENTICATOR_MGMT_H
#define _AUTHENTICATOR_MGMT_H

//Dependencies
#include "authenticator/authenticator.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Authenticator related functions
void authenticatorMgmtLock(AuthenticatorContext *context);
void authenticatorMgmtUnlock(AuthenticatorContext *context);

error_t authenticatorMgmtSetInitialize(AuthenticatorContext *context,
   uint_t portIndex, bool_t initialize, bool_t commit);

error_t authenticatorMgmtSetReauthenticate(AuthenticatorContext *context,
   uint_t portIndex, bool_t reAuthenticate, bool_t commit);

error_t authenticatorMgmtSetPortControl(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortMode portControl, bool_t commit);

error_t authenticatorMgmtSetQuietPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t quietPeriod, bool_t commit);

error_t authenticatorMgmtSetServerTimeout(AuthenticatorContext *context,
   uint_t portIndex, uint_t serverTimeout, bool_t commit);

error_t authenticatorMgmtSetReAuthPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t reAuthPeriod, bool_t commit);

error_t authenticatorMgmtSetReAuthEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t reAuthEnabled, bool_t commit);

error_t authenticatorMgmtSetKeyTxEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t keyTxEnabled, bool_t commit);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
