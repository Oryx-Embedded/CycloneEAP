/**
 * @file supplicant.c
 * @brief 802.1X supplicant
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
#define TRACE_LEVEL SUPPLICANT_TRACE_LEVEL

//Dependencies
#include "supplicant/supplicant.h"
#include "supplicant/supplicant_fsm.h"
#include "supplicant/supplicant_misc.h"
#include "eap/eap_tls.h"
#include "debug.h"

//Check EAP library configuration
#if (SUPPLICANT_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains 802.1X supplicant settings
 **/

void supplicantGetDefaultSettings(SupplicantSettings *settings)
{
   //Default task parameters
   settings->task = OS_TASK_DEFAULT_PARAMS;
   settings->task.stackSize = SUPPLICANT_STACK_SIZE;
   settings->task.priority = SUPPLICANT_PRIORITY;

   //The supplicant is not bound to any interface
   settings->interface = NULL;
   //Port index
   settings->portIndex = 0;

#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   //Pseudo-random number generator
   settings->prngAlgo = NULL;
   settings->prngContext = NULL;
#endif

#if (EAP_TLS_SUPPORT == ENABLED)
   //TLS negotiation initialization callback function
   settings->tlsInitCallback = NULL;
   //TLS negotiation completion callback function
   settings->tlsCompleteCallback = NULL;
#endif

   //Supplicant PAE state change callback function
   settings->paeStateChangeCallback = NULL;
   //Supplicant backend state change callback function
   settings->backendStateChangeCallback = NULL;
   //EAP peer state change callback function
   settings->eapPeerStateChangeCallback = NULL;
   //Tick callback function
   settings->tickCallback = NULL;
}


/**
 * @brief Initialize 802.1X supplicant context
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] settings 802.1X supplicant specific settings
 * @return Error code
 **/

error_t supplicantInit(SupplicantContext *context,
   const SupplicantSettings *settings)
{
   error_t error;

   //Debug message
   TRACE_INFO("Initializing 802.1X supplicant...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Clear supplicant context
   osMemset(context, 0, sizeof(SupplicantContext));

   //Initialize task parameters
   context->taskParams = settings->task;
   context->taskId = OS_INVALID_TASK_ID;

   //Attach TCP/IP stack context
   if(settings->interface != NULL)
   {
      context->netContext = settings->interface->netContext;
   }
   else
   {
      context->netContext = NULL;
   }

   //Save user settings
   context->interface = settings->interface;
   context->portIndex = settings->portIndex;
   context->paeStateChangeCallback = settings->paeStateChangeCallback;
   context->backendStateChangeCallback = settings->backendStateChangeCallback;
   context->eapPeerStateChangeCallback = settings->eapPeerStateChangeCallback;
   context->tickCallback = settings->tickCallback;

#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   //Verify that the PRNG is properly set
   if(settings->prngAlgo == NULL || settings->prngContext == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Pseudo-random number generator
   context->prngAlgo = settings->prngAlgo;
   context->prngContext = settings->prngContext;
#endif

#if (EAP_TLS_SUPPORT == ENABLED)
   //TLS negotiation initialization callback function
   context->tlsInitCallback = settings->tlsInitCallback;
   //TLS negotiation completion callback function
   context->tlsCompleteCallback = settings->tlsCompleteCallback;
#endif

   //Default value of parameters
   context->portControl = SUPPLICANT_PORT_MODE_AUTO;
   context->userLogoff = FALSE;
   context->heldPeriod = SUPPLICANT_DEFAULT_HELD_PERIOD;
   context->authPeriod = SUPPLICANT_DEFAULT_AUTH_PERIOD;
   context->startPeriod = SUPPLICANT_DEFAULT_START_PERIOD;
   context->maxStart = SUPPLICANT_DEFAULT_MAX_START;
   context->clientTimeout = EAP_DEFAULT_CLIENT_TIMEOUT;

   //Initialize supplicant state machine
   supplicantInitFsm(context);

   //Start of exception handling block
   do
   {
      //Create a mutex to prevent simultaneous access to 802.1X supplicant
      //context
      if(!osCreateMutex(&context->mutex))
      {
         //Failed to create mutex
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //Create an event object to poll the state of the raw socket
      if(!osCreateEvent(&context->event))
      {
         //Failed to create event
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

#if (EAP_TLS_SUPPORT == ENABLED)
      //Initialize TLS session state
      error = tlsInitSessionState(&context->tlsSession);
      //Any error to report?
      if(error)
      {
         break;
      }
#endif

      //Successful initialization
      error = NO_ERROR;

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      supplicantDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Set user name
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] username NULL-terminated string containing the user name
 * @return Error code
 **/

error_t supplicantSetUsername(SupplicantContext *context,
   const char_t *username)
{
   //Check parameters
   if(context == NULL || username == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Make sure the length of the user name is acceptable
   if(osStrlen(username) > SUPPLICANT_MAX_USERNAME_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);
   //Save user name
   osStrcpy(context->username, username);
   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set password
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] password NULL-terminated string containing the password
 * @return Error code
 **/

error_t supplicantSetPassword(SupplicantContext *context,
   const char_t *password)
{
#if (EAP_MD5_SUPPORT == ENABLED || EAP_MSCHAPV2_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || password == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Make sure the length of the password is acceptable
   if(osStrlen(password) > SUPPLICANT_MAX_PASSWORD_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);

   //Erase the existing password, if any
   cryptoZeroizeMem(context->password, SUPPLICANT_MAX_PASSWORD_LEN);
   //Save the new password
   osStrcpy(context->password, password);

   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the value of the heldPeriod parameter
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] heldPeriod Value of the heldPeriod parameter
 * @return Error code
 **/

error_t supplicantSetHeldPeriod(SupplicantContext *context, uint_t heldPeriod)
{
   //Check parameters
   if(context == NULL || heldPeriod == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);
   //Save parameter value
   context->heldPeriod = heldPeriod;
   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the authPeriod parameter
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] authPeriod Value of the authPeriod parameter
 * @return Error code
 **/

error_t supplicantSetAuthPeriod(SupplicantContext *context, uint_t authPeriod)
{
   //Check parameters
   if(context == NULL || authPeriod == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);
   //Save parameter value
   context->authPeriod = authPeriod;
   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the startPeriod parameter
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] startPeriod Value of the startPeriod parameter
 * @return Error code
 **/

error_t supplicantSetStartPeriod(SupplicantContext *context, uint_t startPeriod)
{
   //Check parameters
   if(context == NULL || startPeriod == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);
   //Save parameter value
   context->startPeriod = startPeriod;
   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the maxStart parameter
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] maxStart Value of the maxStart parameter
 * @return Error code
 **/

error_t supplicantSetMaxStart(SupplicantContext *context, uint_t maxStart)
{
   //Check parameters
   if(context == NULL || maxStart == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);

   //Save parameter value
   context->maxStart = maxStart;

   //Update supplicant state machines
   if(context->running)
   {
      supplicantFsm(context);
   }

   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the clientTimeout parameter
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] clientTimeout Value of the clientTimeout parameter
 * @return Error code
 **/

error_t supplicantSetClientTimeout(SupplicantContext *context,
   uint_t clientTimeout)
{
   //Check parameters
   if(context == NULL || clientTimeout == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);
   //Save parameter value
   context->clientTimeout = clientTimeout;
   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the value of the portControl variable
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] portControl Value of the portControl variable
 * @return Error code
 **/

error_t supplicantSetPortControl(SupplicantContext *context,
   SupplicantPortMode portControl)
{
   //Make sure the 802.1X supplicant context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);

   //The portControl variable is used to switch between the auto and non-auto
   //modes of operation of the supplicant PAE state machine
   context->portControl = portControl;

   //Update supplicant state machines
   if(context->running)
   {
      supplicantFsm(context);
   }

   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Perform user logon
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

error_t supplicantLogOn(SupplicantContext *context)
{
   //Make sure the 802.1X supplicant context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);

   //The userLogoff variable is controlled externally to the state machine and
   //reflects the operation of the process in the supplicant system that
   //controls the logged on/logged off state of the user of the system
   context->userLogoff = FALSE;

   //Update supplicant state machines
   if(context->running)
   {
      supplicantFsm(context);
   }

   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Perform user logoff
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

error_t supplicantLogOff(SupplicantContext *context)
{
   //Make sure the 802.1X supplicant context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the 802.1X supplicant context
   osAcquireMutex(&context->mutex);

   //The userLogoff variable is controlled externally to the state machine and
   //reflects the operation of the process in the supplicant system that
   //controls the logged on/logged off state of the user of the system
   context->userLogoff = TRUE;

   //Update supplicant state machines
   if(context->running)
   {
      supplicantFsm(context);
   }

   //Release exclusive access to the 802.1X supplicant context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Start 802.1X supplicant
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

error_t supplicantStart(SupplicantContext *context)
{
   error_t error;

   //Make sure the supplicant context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Debug message
   TRACE_INFO("Starting 802.1X supplicant...\r\n");

   //Make sure the supplicant is not already running
   if(context->running)
   {
      return ERROR_ALREADY_RUNNING;
   }

   //Start of exception handling block
   do
   {
      //Open a raw socket
      context->socket = socketOpenEx(context->netContext, SOCKET_TYPE_RAW_ETH,
         ETH_TYPE_EAPOL);
      //Failed to open socket?
      if(context->socket == NULL)
      {
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Force the socket to operate in non-blocking mode
      error = socketSetTimeout(context->socket, 0);
      //Any error to report?
      if(error)
      {
         break;
      }

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->socket, context->interface);
      //Any error to report?
      if(error)
      {
         break;
      }

      //The PAE group address is one of the reserved set of group MAC addresses
      //that are not forwarded by MAC Bridges (refer to IEEE Std 802.1X-2010,
      //section 7.8)
      error = supplicantAcceptPaeGroupAddr(context);
      //Any error to report?
      if(error)
      {
         break;
      }

      //Start the supplicant
      context->stop = FALSE;
      context->running = TRUE;

      //Save current time
      context->timestamp = osGetSystemTime();

      //Reinitialize supplicant state machine
      supplicantInitFsm(context);

      //Create a task
      context->taskId = osCreateTask("Supplicant", (OsTaskCode) supplicantTask,
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
      supplicantDropPaeGroupAddr(context);

      //Close the raw socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Return status code
   return error;
}


/**
 * @brief Stop 802.1X supplicant
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

error_t supplicantStop(SupplicantContext *context)
{
   //Make sure the supplicant context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Debug message
   TRACE_INFO("Stopping 802.1X supplicant...\r\n");

   //Check whether the supplicant is running
   if(context->running)
   {
#if (NET_RTOS_SUPPORT == ENABLED)
      //Stop the supplicant
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }
#endif

#if (EAP_TLS_SUPPORT == ENABLED)
      //Close TLS session
      eapCloseTls(context, ERROR_SERVICE_CLOSING);
#endif

      //Remove the PAE group address from the static MAC table
      supplicantDropPaeGroupAddr(context);

      //Close the raw socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief 802.1X supplicant task
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantTask(SupplicantContext *context)
{
   systime_t time;
   systime_t timeout;
   SocketEventDesc eventDesc;

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
      if((time - context->timestamp) < SUPPLICANT_TICK_INTERVAL)
      {
         timeout = context->timestamp + SUPPLICANT_TICK_INTERVAL - time;
      }
      else
      {
         timeout = 0;
      }

      //Specify the events the application is interested in
      eventDesc.socket = context->socket;
      eventDesc.eventMask = SOCKET_EVENT_RX_READY;
      eventDesc.eventFlags = 0;

      //Wait for an event
      socketPoll(&eventDesc, 1, &context->event, timeout);

      //Stop request?
      if(context->stop)
      {
         //Stop supplicant operation
         context->running = FALSE;
         //Task epilogue
         osExitTask();
         //Kill ourselves
         osDeleteTask(OS_SELF_TASK_ID);
      }

      //Any EAPOL packet received?
      if(eventDesc.eventFlags != 0)
      {
         //Acquire exclusive access to the 802.1X supplicant context
         osAcquireMutex(&context->mutex);
         //Process incoming EAPOL packet
         supplicantProcessEapolPdu(context);
         //Release exclusive access to the 802.1X supplicant context
         osReleaseMutex(&context->mutex);
      }

      //Get current time
      time = osGetSystemTime();

      //Timers have a resolution of one second
      if((time - context->timestamp) >= SUPPLICANT_TICK_INTERVAL)
      {
         //Acquire exclusive access to the 802.1X supplicant context
         osAcquireMutex(&context->mutex);
         //Handle periodic operations
         supplicantTick(context);
         //Release exclusive access to the 802.1X supplicant context
         osReleaseMutex(&context->mutex);

         //Save current time
         context->timestamp = time;
      }

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release 802.1X supplicant context
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantDeinit(SupplicantContext *context)
{
   //Make sure the 802.1X supplicant context is valid
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteMutex(&context->mutex);
      osDeleteEvent(&context->event);

#if (EAP_TLS_SUPPORT == ENABLED)
      //Release TLS session state
      tlsFreeSessionState(&context->tlsSession);
#endif

      //Clear supplicant context
      cryptoZeroizeMem(context, sizeof(SupplicantContext));
   }
}

#endif
