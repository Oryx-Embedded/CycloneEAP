/**
 * @file ieee8021_pae_mib_module.h
 * @brief Port Access Control MIB module
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

#ifndef _IEEE8021_PAE_MIB_MODULE_H
#define _IEEE8021_PAE_MIB_MODULE_H

//Dependencies
#include "mibs/mib_common.h"
#include "eap/eap.h"
#include "authenticator/authenticator.h"

//Port Access Control MIB module support
#ifndef IEEE8021_PAE_MIB_SUPPORT
   #define IEEE8021_PAE_MIB_SUPPORT DISABLED
#elif (IEEE8021_PAE_MIB_SUPPORT != ENABLED && IEEE8021_PAE_MIB_SUPPORT != DISABLED)
   #error IEEE8021_PAE_MIB_SUPPORT parameter is not valid
#endif

//Support for SET operations
#ifndef IEEE8021_PAE_MIB_SET_SUPPORT
   #define IEEE8021_PAE_MIB_SET_SUPPORT DISABLED
#elif (IEEE8021_PAE_MIB_SET_SUPPORT != ENABLED && IEEE8021_PAE_MIB_SET_SUPPORT != DISABLED)
   #error IEEE8021_PAE_MIB_SET_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Administrative state for port access control
 **/

typedef enum
{
   IEEE8021_PAE_MIB_SYS_AUTH_CONTROL_ENABLED  = 1, ///<enabled
   IEEE8021_PAE_MIB_SYS_AUTH_CONTROL_DISABLED = 2  ///<disabled
} Ieee8021PaeMibSysPortControl;


/**
 * @brief Port capabilities
 **/

typedef enum
{
   IEEE8021_PAE_MIB_PORT_CAP_AUTH = 0x01, ///<Authenticator functions are supported
   IEEE8021_PAE_MIB_PORT_CAP_SUPP = 0x02  ///<Supplicant functions are supported
} Ieee8021PaeMibPortCap;


/**
 * @brief Authenticator PAE states
 **/

typedef enum
{
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_INITIALIZE     = 1, ///<initialize
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_DISCONNECTED   = 2, ///<disconnected
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_CONNECTING     = 3, ///<connecting
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_AUTHENTICATING = 4, ///<authenticating
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_AUTHENTICATED  = 5, ///<authenticated
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_ABORTING       = 6, ///<aborting
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_HELD           = 7, ///<held
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_FORCE_AUTH     = 8, ///<forceAuth
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_FORCE_UNAUTH   = 9, ///<forceUnauth
   IEEE8021_PAE_MIB_AUTH_PAE_STATE_RESTART        = 10 ///<restart
} Ieee8021PaeMibAuthPaeState;


/**
 * @brief Backend authentication states
 **/

typedef enum
{
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_REQUEST    = 1, ///<request
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_RESPONSE   = 2, ///<response
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_SUCCESS    = 3, ///<success
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_FAIL       = 4, ///<fail
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_TIMEOUT    = 5, ///<timeout
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_IDLE       = 6, ///<idle
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_INITIALIZE = 7, ///<initialize
   IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_IGNORE     = 8  ///<ignore
} Ieee8021PaeMibAuthBackendState;


/**
 * @brief Controlled directions
 **/

typedef enum
{
   IEEE8021_PAE_MIB_CONTROL_DIR_BOTH = 0, ///<both
   IEEE8021_PAE_MIB_CONTROL_DIR_IN   = 1  ///<in
} Ieee8021PaeMibControlledDir;


/**
 * @brief Port status
 **/

typedef enum
{
   IEEE8021_PAE_MIB_PORT_STATUS_AUTH   = 1, ///<authorized
   IEEE8021_PAE_MIB_PORT_STATUS_UNAUTH = 2  ///<unauthorized
} Ieee8021PaeMibPortStatus;


/**
 * @brief Port control
 **/

typedef enum
{
   IEEE8021_PAE_MIB_PORT_CONTROL_FORCE_UNAUTH = 1, ///<forceUnauthorized
   IEEE8021_PAE_MIB_PORT_CONTROL_AUTO         = 2, ///<auto
   IEEE8021_PAE_MIB_PORT_CONTROL_FORCE_AUTH   = 3  ///<forceAuthorized
} Ieee8021PaeMibPortControl;


/**
 * @brief Authentication method
 **/

typedef enum
{
   IEEE8021_PAE_MIB_AUTH_METHOD_REMOTE_AUTH_SERVER = 1, ///<remoteAuthServer
   IEEE8021_PAE_MIB_AUTH_METHOD_LOCAL_AUTH_SERVER  = 2  ///<localAuthServer
} Ieee8021PaeMibAuthMethod;


/**
 * @brief Session terminate cause
 **/

typedef enum
{
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_SUPPLICANT_LOGOFF         = 1,  ///<supplicantLogoff
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_PORT_FAILURE              = 2,  ///<portFailure
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_SUPPLICANT_RESTART        = 3,  ///<supplicantRestart
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_REAUTH_FAILED             = 4,  ///<reauthFailed
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_AUTH_CONTROL_FORCE_UNAUTH = 5,  ///<authControlForceUnauth
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_PORT_REINIT               = 6,  ///<portReInit
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_PORT_ADMIN_DISABLED       = 7,  ///<portAdminDisabled
   IEEE8021_PAE_MIB_TERMINATE_CAUSE_NOT_TERMINATED_YET        = 999 ///<notTerminatedYet
} Ieee8021PaeMibTerminateCause;


/**
 * @brief Port Access Control MIB base
 **/

typedef struct
{
#if (AUTHENTICATOR_SUPPORT == ENABLED)
   AuthenticatorContext *authContext;
#endif
} Ieee8021PaeMibBase;


//Port Access Control MIB related constants
extern Ieee8021PaeMibBase ieee8021PaeMibBase;
extern const MibObject ieee8021PaeMibObjects[];
extern const MibModule ieee8021PaeMibModule;

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
