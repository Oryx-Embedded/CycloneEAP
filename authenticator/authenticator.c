/**
 * @file authenticator.c
 * @brief 802.1X authenticator
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
#include "authenticator/authenticator_misc.h"
#include "radius/radius.h"
#include "debug.h"

//Check EAP library configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains 802.1X authenticator settings
 **/

void authenticatorGetDefaultSettings(AuthenticatorSettings *settings)
{
   //Default task parameters
   settings->task = OS_TASK_DEFAULT_PARAMS;
   settings->task.stackSize = AUTHENTICATOR_STACK_SIZE;
   settings->task.priority = AUTHENTICATOR_PRIORITY;

   //Peer interface
   settings->interface = NULL;

   //Number of ports
   settings->numPorts = 0;
   //Ports
   settings->ports = NULL;

   //RADIUS server interface
   settings->serverInterface = NULL;
   //Switch port used to reach the RADIUS server
   settings->serverPortIndex = 0;

   //RADIUS server's IP address
   settings->serverIpAddr = IP_ADDR_UNSPECIFIED;
   //RADIUS server's port
   settings->serverPort = RADIUS_PORT;

   //Pseudo-random number generator
   settings->prngAlgo = NULL;
   settings->prngContext = NULL;

   //Authenticator PAE state change callback function
   settings->paeStateChangeCallback = NULL;
   //Backend authentication state change callback function
   settings->backendStateChangeCallback = NULL;
   //Reauthentication timer state change callback function
   settings->reauthTimerStateChangeCallback = NULL;
   //EAP full authenticator state change callback function
   settings->eapFullAuthStateChangeCallback = NULL;
   //Tick callback function
   settings->tickCallback = NULL;
}


/**
 * @brief Initialize 802.1X authenticator context
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] settings 802.1X authenticator specific settings
 * @return Error code
 **/

error_t authenticatorInit(AuthenticatorContext *context,
   const AuthenticatorSettings *settings)
{
   error_t error;
   uint_t i;
   AuthenticatorPort *port;

   //Debug message
   TRACE_INFO("Initializing 802.1X authenticator...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   if(settings->interface == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   if(settings->numPorts == 0 || settings->ports == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   if(settings->prngAlgo == NULL || settings->prngContext == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Clear authenticator context
   osMemset(context, 0, sizeof(AuthenticatorContext));

   //Initialize task parameters
   context->taskParams = settings->task;
   context->taskId = OS_INVALID_TASK_ID;

   //Attach TCP/IP stack context
   context->netContext = settings->interface->netContext;

   //Save user settings
   context->interface = settings->interface;
   context->numPorts = settings->numPorts;
   context->ports = settings->ports;
   context->serverPortIndex = settings->serverPortIndex;
   context->serverIpAddr = settings->serverIpAddr;
   context->serverPort = settings->serverPort;
   context->prngAlgo = settings->prngAlgo;
   context->prngContext = settings->prngContext;
   context->paeStateChangeCallback = settings->paeStateChangeCallback;
   context->backendStateChangeCallback = settings->backendStateChangeCallback;
   context->reauthTimerStateChangeCallback = settings->reauthTimerStateChangeCallback;
   context->eapFullAuthStateChangeCallback = settings->eapFullAuthStateChangeCallback;
   context->tickCallback = settings->tickCallback;

   //Select the interface used to reach the RADIUS server
   if(settings->serverInterface != NULL)
   {
      context->serverInterface = settings->serverInterface;
   }
   else
   {
      context->serverInterface = settings->interface;
   }

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current port
      port = &context->ports[i];

      //Clear port context
      osMemset(port, 0, sizeof(AuthenticatorPort));

      //Attach authenticator context to each port
      port->context = context;
      //Set port index
      port->portIndex = i + 1;

      //Default value of parameters
      port->portControl = AUTHENTICATOR_PORT_MODE_FORCE_AUTH;
      port->quietPeriod = AUTHENTICATOR_DEFAULT_QUIET_PERIOD;
      port->serverTimeout = AUTHENTICATOR_DEFAULT_SERVER_TIMEOUT;
      port->maxRetrans = AUTHENTICATOR_DEFAULT_MAX_RETRANS;
      port->reAuthMax = AUTHENTICATOR_DEFAULT_REAUTH_MAX;
      port->reAuthPeriod = AUTHENTICATOR_DEFAULT_REAUTH_PERIOD;
      port->reAuthEnabled = FALSE;
      port->keyTxEnabled = FALSE;

      //Each port must assigned a unique MAC address
      authenticatorGeneratePortAddr(port);

      //The port is down
      port->sessionStats.sessionTerminateCause =
         AUTHENTICATOR_TERMINATE_CAUSE_PORT_FAILURE;
   }

   //Initialize authenticator state machine
   authenticatorInitFsm(context);

   //Start of exception handling block
   do
   {
      //Create a mutex to prevent simultaneous access to 802.1X authenticator
      //context
      if(!osCreateMutex(&context->mutex))
      {
         //Failed to create mutex
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //Create an event object to poll the state of sockets
      if(!osCreateEvent(&context->event))
      {
         //Failed to create event
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //Successful initialization
      error = NO_ERROR;

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      authenticatorDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Specify the IP address of the RADIUS server
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] serverIpAddr IP address of the RADIUS server
 * @param[in] serverPort Port number
 * @return Error code
 **/

error_t authenticatorSetServerAddr(AuthenticatorContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   //Check parameters
   if(context == NULL || serverIpAddr == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);

   //Save the IP address and the port number of the RADIUS server
   context->serverIpAddr = *serverIpAddr;
   context->serverPort = serverPort;

   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set RADIUS server's key
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key, in bytes
 * @return Error code
 **/

error_t authenticatorSetServerKey(AuthenticatorContext *context,
   const uint8_t *key, size_t keyLen)
{
   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Check parameters
   if(key == NULL && keyLen != 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Check the length of the key
   if(keyLen > AUTHENTICATOR_MAX_SERVER_KEY_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);

   //Erase the existing key, if any
   cryptoZeroizeMem(context->serverKey, AUTHENTICATOR_MAX_SERVER_KEY_LEN);
   //Copy the new key
   osMemcpy(context->serverKey, key, keyLen);
   //Save the length of the key
   context->serverKeyLen = keyLen;

   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Reinitialize the specified port
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @return Error code
 **/

error_t authenticatorInitPort(AuthenticatorContext *context,
   uint_t portIndex)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the 802.1X authenticator context
      osAcquireMutex(&context->mutex);

      //Perform management operation
      error = authenticatorMgmtSetInitialize(context, portIndex, TRUE,
         TRUE);

      //Release exclusive access to the 802.1X authenticator context
      osReleaseMutex(&context->mutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Force the authenticator to reauthenticate the supplicant
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @return Error code
 **/

error_t authenticatorReauthenticate(AuthenticatorContext *context,
   uint_t portIndex)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the 802.1X authenticator context
      osAcquireMutex(&context->mutex);

      //Perform management operation
      error = authenticatorMgmtSetReauthenticate(context, portIndex, TRUE,
         TRUE);

      //Release exclusive access to the 802.1X authenticator context
      osReleaseMutex(&context->mutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set the value of the AuthControlledPortControl parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] portControl Value of the AuthControlledPortControl parameter
 * @return Error code
 **/

error_t authenticatorSetPortControl(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortMode portControl)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the 802.1X authenticator context
      osAcquireMutex(&context->mutex);

      //Perform management operation
      error = authenticatorMgmtSetPortControl(context, portIndex, portControl,
         TRUE);

      //Release exclusive access to the 802.1X authenticator context
      osReleaseMutex(&context->mutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set the value of the quietPeriod parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] quietPeriod Value of the quietPeriod parameter
 * @return Error code
 **/

error_t authenticatorSetQuietPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t quietPeriod)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the 802.1X authenticator context
      osAcquireMutex(&context->mutex);

      //Perform management operation
      error = authenticatorMgmtSetQuietPeriod(context, portIndex, quietPeriod,
         TRUE);

      //Release exclusive access to the 802.1X authenticator context
      osReleaseMutex(&context->mutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set the value of the serverTimeout parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] serverTimeout Value of the serverTimeout parameter
 * @return Error code
 **/

error_t authenticatorSetServerTimeout(AuthenticatorContext *context,
   uint_t portIndex, uint_t serverTimeout)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the 802.1X authenticator context
      osAcquireMutex(&context->mutex);

      //Perform management operation
      error = authenticatorMgmtSetServerTimeout(context, portIndex,
         serverTimeout, TRUE);

      //Release exclusive access to the 802.1X authenticator context
      osReleaseMutex(&context->mutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set the value of the reAuthEnabled parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] reAuthEnabled Value of the reAuthEnabled parameter
 * @return Error code
 **/

error_t authenticatorSetReAuthEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t reAuthEnabled)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the 802.1X authenticator context
      osAcquireMutex(&context->mutex);

      //Perform management operation
      error = authenticatorMgmtSetReAuthEnabled(context, portIndex,
         reAuthEnabled, TRUE);

      //Release exclusive access to the 802.1X authenticator context
      osReleaseMutex(&context->mutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Set the value of the reAuthPeriod parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[in] reAuthPeriod Value of the reAuthPeriod parameter
 * @return Error code
 **/

error_t authenticatorSetReAuthPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t reAuthPeriod)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Acquire exclusive access to the 802.1X authenticator context
      osAcquireMutex(&context->mutex);

      //Perform management operation
      error = authenticatorMgmtSetReAuthPeriod(context, portIndex,
         reAuthPeriod, TRUE);

      //Release exclusive access to the 802.1X authenticator context
      osReleaseMutex(&context->mutex);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the current value of the AuthControlledPortControl parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] portControl value of the AuthControlledPortControl parameter
 * @return Error code
 **/

error_t authenticatorGetPortControl(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortMode *portControl)
{
   //Check parameters
   if(context == NULL || portControl == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current value of the parameter
   *portControl = context->ports[portIndex - 1].portControl;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current value of the quietPeriod parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] quietPeriod value of the quietPeriod parameter
 * @return Error code
 **/

error_t authenticatorGetQuietPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t *quietPeriod)
{
   //Check parameters
   if(context == NULL || quietPeriod == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current value of the parameter
   *quietPeriod = context->ports[portIndex - 1].quietPeriod;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current value of the serverTimeout parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] serverTimeout value of the serverTimeout parameter
 * @return Error code
 **/

error_t authenticatorGetServerTimeout(AuthenticatorContext *context,
   uint_t portIndex, uint_t *serverTimeout)
{
   //Check parameters
   if(context == NULL || serverTimeout == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current value of the parameter
   *serverTimeout = context->ports[portIndex - 1].serverTimeout;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current value of the reAuthEnabled parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] reAuthEnabled value of the reAuthEnabled parameter
 * @return Error code
 **/

error_t authenticatorGetReAuthEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t *reAuthEnabled)
{
   //Check parameters
   if(context == NULL || reAuthEnabled == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current value of the parameter
   *reAuthEnabled = context->ports[portIndex - 1].reAuthEnabled;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current value of the reAuthPeriod parameter
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] reAuthPeriod value of the reAuthPeriod parameter
 * @return Error code
 **/

error_t authenticatorGetReAuthPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t *reAuthPeriod)
{
   //Check parameters
   if(context == NULL || reAuthPeriod == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current value of the parameter
   *reAuthPeriod = context->ports[portIndex - 1].reAuthPeriod;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current value of the AuthControlledPortStatus variable
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] portStatus Current value of the AuthControlledPortStatus variable
 * @return Error code
 **/

error_t authenticatorGetPortStatus(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortStatus *portStatus)
{
   //Check parameters
   if(context == NULL || portStatus == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current value of the variable
   *portStatus = context->ports[portIndex - 1].authPortStatus;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current state of the authenticator PAE state state machine
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] paeState Current state of the authenticator PAE state machine
 * @return Error code
 **/

error_t authenticatorGetPaeState(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPaeState *paeState)
{
   //Check parameters
   if(context == NULL || paeState == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current state
   *paeState = context->ports[portIndex - 1].authPaeState;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current state of the backend authentication state machine
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] backendState Current state of the backend authentication state
 *   machine
 * @return Error code
 **/

error_t authenticatorGetBackendState(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorBackendState *backendState)
{
   //Check parameters
   if(context == NULL || backendState == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current state
   *backendState = context->ports[portIndex - 1].authBackendState;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current state of the reauthentication timer state machine
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] reauthTimerState Current state of the reauthentication timer state
 *   machine
 * @return Error code
 **/

error_t authenticatorGetReauthTimerState(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorReauthTimerState *reauthTimerState)
{
   //Check parameters
   if(context == NULL || reauthTimerState == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current state
   *reauthTimerState = context->ports[portIndex - 1].reauthTimerState;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the current state of the EAP full authenticator state machine
 * @param[in] context Pointer to the 802.1X authenticator context
 * @param[in] portIndex Port index
 * @param[out] eapFullAuthState Current state of the EAP full authenticator state
 *   machine
 * @return Error code
 **/

error_t authenticatorGetEapFullAuthState(AuthenticatorContext *context,
   uint_t portIndex, EapFullAuthState *eapFullAuthState)
{
   //Check parameters
   if(context == NULL || eapFullAuthState == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the 802.1X authenticator context
   osAcquireMutex(&context->mutex);
   //Get the current state
   *eapFullAuthState = context->ports[portIndex - 1].eapFullAuthState;
   //Release exclusive access to the 802.1X authenticator context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Start 802.1X authenticator
 * @param[in] context Pointer to the 802.1X authenticator context
 * @return Error code
 **/

error_t authenticatorStart(AuthenticatorContext *context)
{
   error_t error;

   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Debug message
   TRACE_INFO("Starting 802.1X authenticator...\r\n");

   //Make sure the authenticator is not already running
   if(context->running)
   {
      return ERROR_ALREADY_RUNNING;
   }

   //Start of exception handling block
   do
   {
      //Open a UDP socket
      context->serverSocket = socketOpenEx(context->netContext,
         SOCKET_TYPE_DGRAM, SOCKET_IP_PROTO_UDP);
      //Failed to open socket?
      if(context->serverSocket == NULL)
      {
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Force the socket to operate in non-blocking mode
      error = socketSetTimeout(context->serverSocket, 0);
      //Any error to report?
      if(error)
      {
         break;
      }

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->serverSocket,
         context->serverInterface);
      //Any error to report?
      if(error)
      {
         break;
      }

      //Open a raw socket
      context->peerSocket = socketOpenEx(context->netContext,
         SOCKET_TYPE_RAW_ETH, ETH_TYPE_EAPOL);
      //Failed to open socket?
      if(context->peerSocket == NULL)
      {
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Force the socket to operate in non-blocking mode
      error = socketSetTimeout(context->peerSocket, 0);
      //Any error to report?
      if(error)
      {
         break;
      }

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->peerSocket, context->interface);
      //Any error to report?
      if(error)
      {
         break;
      }

      //The PAE group address is one of the reserved set of group MAC addresses
      //that are not forwarded by MAC Bridges (refer to IEEE Std 802.1X-2010,
      //section 7.8)
      error = authenticatorAcceptPaeGroupAddr(context);
      //Any error to report?
      if(error)
      {
         break;
      }

      //Start the authenticator
      context->stop = FALSE;
      context->running = TRUE;

      //Save current time
      context->timestamp = osGetSystemTime();

      //Reinitialize authenticator state machine
      authenticatorInitFsm(context);

      //Create a task
      context->taskId = osCreateTask("Authenticator", (OsTaskCode) authenticatorTask,
         context, &context->taskParams);

      //Failed to create task?
      if(context->taskId == OS_INVALID_TASK_ID)
      {
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      context->running = FALSE;

      //Remove the PAE group address from the static MAC table
      authenticatorDropPaeGroupAddr(context);

      //Close the raw socket
      if(context->peerSocket != NULL)
      {
         socketClose(context->peerSocket);
         context->peerSocket = NULL;
      }

      //Close the UDP socket
      if(context->serverSocket != NULL)
      {
         socketClose(context->serverSocket);
         context->serverSocket = NULL;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Stop 802.1X authenticator
 * @param[in] context Pointer to the 802.1X authenticator context
 * @return Error code
 **/

error_t authenticatorStop(AuthenticatorContext *context)
{
   //Make sure the 802.1X authenticator context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Debug message
   TRACE_INFO("Stopping 802.1X authenticator...\r\n");

   //Check whether the authenticator is running
   if(context->running)
   {
#if (NET_RTOS_SUPPORT == ENABLED)
      //Stop the authenticator
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }
#endif

      //Remove the PAE group address from the static MAC table
      authenticatorDropPaeGroupAddr(context);

      //Close the raw socket
      socketClose(context->peerSocket);
      context->peerSocket = NULL;

      //Close the UDP socket
      socketClose(context->serverSocket);
      context->serverSocket = NULL;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief 802.1X authenticator task
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorTask(AuthenticatorContext *context)
{
   systime_t time;
   systime_t timeout;
   SocketEventDesc eventDesc[2];

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Process events
   while(1)
   {
#endif
      //Get current time
      time = osGetSystemTime();

      //Maximum time to wait for an incoming datagram
      if((time - context->timestamp) < AUTHENTICATOR_TICK_INTERVAL)
      {
         timeout = context->timestamp + AUTHENTICATOR_TICK_INTERVAL - time;
      }
      else
      {
         timeout = 0;
      }

      //Specify the events the application is interested in
      eventDesc[0].socket = context->peerSocket;
      eventDesc[0].eventMask = SOCKET_EVENT_RX_READY;
      eventDesc[0].eventFlags = 0;
      eventDesc[1].socket = context->serverSocket;
      eventDesc[1].eventMask = SOCKET_EVENT_RX_READY;
      eventDesc[1].eventFlags = 0;

      //Wait for an event
      socketPoll(eventDesc, 2, &context->event, timeout);

      //Stop request?
      if(context->stop)
      {
         //Stop authenticator operation
         context->running = FALSE;
         //Task epilogue
         osExitTask();
         //Kill ourselves
         osDeleteTask(OS_SELF_TASK_ID);
      }

      //Any EAPOL packet received?
      if(eventDesc[0].eventFlags != 0)
      {
         //Acquire exclusive access to the 802.1X authenticator context
         osAcquireMutex(&context->mutex);
         //Process incoming EAPOL packet
         authenticatorProcessEapolPdu(context);
         //Release exclusive access to the 802.1X authenticator context
         osReleaseMutex(&context->mutex);
      }

      //Any RADIUS packet received?
      if(eventDesc[1].eventFlags != 0)
      {
         //Acquire exclusive access to the 802.1X authenticator context
         osAcquireMutex(&context->mutex);
         //Process incoming RADIUS packet
         authenticatorProcessRadiusPacket(context);
         //Release exclusive access to the 802.1X authenticator context
         osReleaseMutex(&context->mutex);
      }

      //Get current time
      time = osGetSystemTime();

      //Timers have a resolution of one second
      if((time - context->timestamp) >= AUTHENTICATOR_TICK_INTERVAL)
      {
         //Acquire exclusive access to the 802.1X authenticator context
         osAcquireMutex(&context->mutex);
         //Handle periodic operations
         authenticatorTick(context);
         //Release exclusive access to the 802.1X authenticator context
         osReleaseMutex(&context->mutex);

         //Save current time
         context->timestamp = time;
      }

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release 802.1X authenticator context
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorDeinit(AuthenticatorContext *context)
{
   //Make sure the 802.1X authenticator context is valid
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteMutex(&context->mutex);
      osDeleteEvent(&context->event);

      //Clear authenticator context
      cryptoZeroizeMem(context, sizeof(AuthenticatorContext));
   }
}

#endif
