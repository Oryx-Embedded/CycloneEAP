/**
 * @file authenticator_mgmt.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL AUTHENTICATOR_TRACE_LEVEL

//Dependencies
#include "authenticator/authenticator.h"
#include "authenticator/authenticator_mgmt.h"
#include "authenticator/authenticator_fsm.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)


/**
 * @brief Acquire exclusive access to the 802.1X authenticator context
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorMgmtLock(AuthenticatorContext *context)
{
   //Acquire exclusive access
   osAcquireMutex(&context->mutex);
}


/**
 * @brief Release exclusive access to the 802.1X authenticator context
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorMgmtUnlock(AuthenticatorContext *context)
{
   //Release exclusive access
   osReleaseMutex(&context->mutex);
}


/**
 * @brief Force the value of the initialize variable
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] initialize Value of the initialize variable
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetInitialize(AuthenticatorContext *context,
   uint_t portIndex, bool_t initialize, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Setting this variable to FALSE has no effect
      if(initialize)
      {
         //Initialize port
         authenticatorInitPortFsm(port);
         //Update authenticator state machines
         authenticatorFsm(context);

         //The PACP state machines are held in their initial state until
         //initialize is deasserted (refer to IEEE Std 802.1X-2004, section
         //8.2.2.2)
         port->initialize = FALSE;

         //This variable indicates how the session was terminated
         port->sessionStats.sessionTerminateCause =
            AUTHENTICATOR_TERMINATE_CAUSE_PORT_REINIT;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Force the value of the reAuthenticate variable
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] reAuthenticate Value of the reAuthenticate variable
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetReauthenticate(AuthenticatorContext *context,
   uint_t portIndex, bool_t reAuthenticate, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Setting this variable to FALSE has no effect
      if(reAuthenticate)
      {
         //The reAuthenticate variable may be set TRUE by management action
         port->reAuthenticate = TRUE;
         //Update authenticator state machines
         authenticatorFsm(context);
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the AuthControlledPortControl parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] portControl Value of the AuthControlledPortControl parameter
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetPortControl(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortMode portControl, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->portControl = portControl;
      //Update authenticator state machines
      authenticatorFsm(context);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the quietPeriod parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] quietPeriod Value of the quietPeriod parameter
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetQuietPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t quietPeriod, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //The quietPeriod parameter can be set by management to any value in the
   //range from 0 to 65535 s (refer to IEEE Std 802.1X-2004, section 8.2.4.1.2)
   if(quietPeriod > AUTHENTICATOR_MAX_QUIET_PERIOD)
   {
      return ERROR_WRONG_VALUE;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->quietPeriod = quietPeriod;

      //Check whether the quietWhile timer is running
      if(port->quietWhile > 0)
      {
         //Reinitialize quietWhile timer
         port->quietWhile = port->quietPeriod;
      }

      //Update authenticator state machines
      authenticatorFsm(context);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the serverTimeout parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] serverTimeout Value of the serverTimeout parameter
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetServerTimeout(AuthenticatorContext *context,
   uint_t portIndex, uint_t serverTimeout, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //The serverTimeout parameter can be set by management to any value in the
   //range from 1 to X s, where X is an implementation dependent value (refer
   //to IEEE Std 802.1X-2004, section 8.2.9.1.2)
   if(serverTimeout < AUTHENTICATOR_MIN_SERVER_TIMEOUT ||
      serverTimeout > AUTHENTICATOR_MAX_SERVER_TIMEOUT)
   {
      return ERROR_WRONG_VALUE;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->serverTimeout = serverTimeout;

      //Check whether the aWhile timer is running
      if(port->aWhile > 0)
      {
         //Reinitialize aWhile timer
         port->aWhile = port->serverTimeout;
      }

      //Update authenticator state machines
      authenticatorFsm(context);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the reAuthPeriod parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] reAuthPeriod Value of the reAuthPeriod parameter
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetReAuthPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t reAuthPeriod, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //If the value of the reAuthPeriod parameter is outside the specified range,
   //then no action shall be taken
   if(reAuthPeriod < AUTHENTICATOR_MIN_REAUTH_PERIOD ||
      reAuthPeriod > AUTHENTICATOR_MAX_REAUTH_PERIOD)
   {
      return ERROR_WRONG_VALUE;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->reAuthPeriod = reAuthPeriod;

      //Check whether the reAuthWhen timer is running
      if(port->reAuthWhen > 0)
      {
         //Reinitialize reAuthWhen timer
         port->reAuthWhen = port->reAuthPeriod;
      }

      //Update authenticator state machines
      authenticatorFsm(context);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the reAuthEnabled parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] reAuthEnabled Value of the reAuthEnabled parameter
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetReAuthEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t reAuthEnabled, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->reAuthEnabled = reAuthEnabled;
      //Update authenticator state machines
      authenticatorFsm(context);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the KeyTransmissionEnabled parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] keyTxEnabled Value of the KeyTransmissionEnabled parameter
 * @param[in] commit If this flag is TRUE, the authenticator verifies the
 *   parameter value and commits the change if the value is valid. If FALSE,
 *   the authenticator only performs the verification and does not take any
 *   further action
 * @return Error code
 **/

error_t authenticatorMgmtSetKeyTxEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t keyTxEnabled, bool_t commit)
{
   AuthenticatorPort *port;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_WRITE_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->keyTxEnabled = keyTxEnabled;
      //Update authenticator state machines
      authenticatorFsm(context);
   }

   //Successful processing
   return NO_ERROR;
}

#endif
