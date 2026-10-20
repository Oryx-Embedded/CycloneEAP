/**
 * @file authenticator_backend_fsm.h
 * @brief Backend authentication state machine
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

#ifndef _AUTHENTICATOR_BACKEND_FSM_H
#define _AUTHENTICATOR_BACKEND_FSM_H

//Dependencies
#include "authenticator/authenticator.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Backend authentication states
 **/

typedef enum
{
   AUTHENTICATOR_BACKEND_STATE_INITIALIZE = 0,
   AUTHENTICATOR_BACKEND_STATE_IDLE       = 1,
   AUTHENTICATOR_BACKEND_STATE_REQUEST    = 2,
   AUTHENTICATOR_BACKEND_STATE_RESPONSE   = 3,
   AUTHENTICATOR_BACKEND_STATE_IGNORE     = 4,
   AUTHENTICATOR_BACKEND_STATE_FAIL       = 5,
   AUTHENTICATOR_BACKEND_STATE_TIMEOUT    = 6,
   AUTHENTICATOR_BACKEND_STATE_SUCCESS    = 7
} AuthenticatorBackendState;


//Authenticator related functions
void authenticatorBackendInitFsm(AuthenticatorPort *port);
void authenticatorBackendFsm(AuthenticatorPort *port);

void authenticatorBackendChangeState(AuthenticatorPort *port,
   AuthenticatorBackendState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
