/**
 * @file authenticator.h
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
 * @version 2.6.6
 **/

#ifndef _AUTHENTICATOR_H
#define _AUTHENTICATOR_H

//Forward declaration of AuthenticatorContext structure
struct _AuthenticatorContext;
#define AuthenticatorContext struct _AuthenticatorContext

//Forward declaration of AuthenticatorPort structure
struct _AuthenticatorPort;
#define AuthenticatorPort struct _AuthenticatorPort

//Dependencies
#include "eap/eap.h"
#include "eap/eap_full_auth_fsm.h"
#include "authenticator/authenticator_pae_fsm.h"
#include "authenticator/authenticator_backend_fsm.h"
#include "authenticator/authenticator_reauth_timer_fsm.h"
#include "mac/hmac.h"

//802.1X authenticator support
#ifndef AUTHENTICATOR_SUPPORT
   #define AUTHENTICATOR_SUPPORT ENABLED
#elif (AUTHENTICATOR_SUPPORT != ENABLED && AUTHENTICATOR_SUPPORT != DISABLED)
   #error AUTHENTICATOR_SUPPORT parameter is not valid
#endif

//Stack size required to run the 802.1X authenticator
#ifndef AUTHENTICATOR_STACK_SIZE
   #define AUTHENTICATOR_STACK_SIZE 750
#elif (AUTHENTICATOR_STACK_SIZE < 1)
   #error AUTHENTICATOR_STACK_SIZE parameter is not valid
#endif

//Priority at which the 802.1X authenticator should run
#ifndef AUTHENTICATOR_PRIORITY
   #define AUTHENTICATOR_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//802.1X authenticator tick interval (in milliseconds)
#ifndef AUTHENTICATOR_TICK_INTERVAL
   #define AUTHENTICATOR_TICK_INTERVAL 1000
#elif (AUTHENTICATOR_TICK_INTERVAL < 10)
   #error AUTHENTICATOR_TICK_INTERVAL parameter is not valid
#endif

//Size of the transmission buffer
#ifndef AUTHENTICATOR_TX_BUFFER_SIZE
   #define AUTHENTICATOR_TX_BUFFER_SIZE 1500
#elif (AUTHENTICATOR_TX_BUFFER_SIZE < 1)
   #error AUTHENTICATOR_TX_BUFFER_SIZE parameter is not valid
#endif

//Size of the reception buffer
#ifndef AUTHENTICATOR_RX_BUFFER_SIZE
   #define AUTHENTICATOR_RX_BUFFER_SIZE 1500
#elif (AUTHENTICATOR_RX_BUFFER_SIZE < 1)
   #error AUTHENTICATOR_RX_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of the RADIUS server's key
#ifndef AUTHENTICATOR_MAX_SERVER_KEY_LEN
   #define AUTHENTICATOR_MAX_SERVER_KEY_LEN 64
#elif (AUTHENTICATOR_MAX_SERVER_KEY_LEN < 1)
   #error AUTHENTICATOR_MAX_SERVER_KEY_LEN parameter is not valid
#endif

//Default value for the quietPeriod parameter
#ifndef AUTHENTICATOR_DEFAULT_QUIET_PERIOD
   #define AUTHENTICATOR_DEFAULT_QUIET_PERIOD 60
#elif (AUTHENTICATOR_DEFAULT_QUIET_PERIOD < 0)
   #error AUTHENTICATOR_DEFAULT_QUIET_PERIOD parameter is not valid
#endif

//Maximum acceptable value for the quietPeriod parameter
#ifndef AUTHENTICATOR_MAX_QUIET_PERIOD
   #define AUTHENTICATOR_MAX_QUIET_PERIOD 65535
#elif (AUTHENTICATOR_MAX_QUIET_PERIOD < AUTHENTICATOR_DEFAULT_QUIET_PERIOD)
   #error AUTHENTICATOR_MAX_QUIET_PERIOD parameter is not valid
#endif

//Maximum number of reauthentication attempts
#ifndef AUTHENTICATOR_DEFAULT_REAUTH_MAX
   #define AUTHENTICATOR_DEFAULT_REAUTH_MAX 2
#elif (AUTHENTICATOR_DEFAULT_REAUTH_MAX < 0)
   #error AUTHENTICATOR_DEFAULT_REAUTH_MAX parameter is not valid
#endif

//Minimum acceptable value for the serverTimeout parameter
#ifndef AUTHENTICATOR_MIN_SERVER_TIMEOUT
   #define AUTHENTICATOR_MIN_SERVER_TIMEOUT 1
#elif (AUTHENTICATOR_MIN_SERVER_TIMEOUT < 0)
   #error AUTHENTICATOR_MIN_SERVER_TIMEOUT parameter is not valid
#endif

//Default value for the serverTimeout parameter
#ifndef AUTHENTICATOR_DEFAULT_SERVER_TIMEOUT
   #define AUTHENTICATOR_DEFAULT_SERVER_TIMEOUT 30
#elif (AUTHENTICATOR_DEFAULT_SERVER_TIMEOUT < AUTHENTICATOR_MIN_SERVER_TIMEOUT)
   #error AUTHENTICATOR_DEFAULT_SERVER_TIMEOUT parameter is not valid
#endif

//Maximum acceptable value for the serverTimeout parameter
#ifndef AUTHENTICATOR_MAX_SERVER_TIMEOUT
   #define AUTHENTICATOR_MAX_SERVER_TIMEOUT 3600
#elif (AUTHENTICATOR_MAX_SERVER_TIMEOUT < AUTHENTICATOR_DEFAULT_SERVER_TIMEOUT)
   #error AUTHENTICATOR_MAX_SERVER_TIMEOUT parameter is not valid
#endif

//Maximum number of retransmissions before aborting
#ifndef AUTHENTICATOR_DEFAULT_MAX_RETRANS
   #define AUTHENTICATOR_DEFAULT_MAX_RETRANS 4
#elif (AUTHENTICATOR_DEFAULT_MAX_RETRANS < 0)
   #error AUTHENTICATOR_DEFAULT_MAX_RETRANS parameter is not valid
#endif

//Minimum acceptable value for the reAuthPeriod parameter
#ifndef AUTHENTICATOR_MIN_REAUTH_PERIOD
   #define AUTHENTICATOR_MIN_REAUTH_PERIOD 10
#elif (AUTHENTICATOR_MIN_REAUTH_PERIOD < 0)
   #error AUTHENTICATOR_MIN_REAUTH_PERIOD parameter is not valid
#endif

//Default value for the reAuthPeriod parameter
#ifndef AUTHENTICATOR_DEFAULT_REAUTH_PERIOD
   #define AUTHENTICATOR_DEFAULT_REAUTH_PERIOD 3600
#elif (AUTHENTICATOR_DEFAULT_REAUTH_PERIOD < AUTHENTICATOR_MIN_REAUTH_PERIOD)
   #error AUTHENTICATOR_DEFAULT_REAUTH_PERIOD parameter is not valid
#endif

//Maximum acceptable value for the reAuthPeriod parameter
#ifndef AUTHENTICATOR_MAX_REAUTH_PERIOD
   #define AUTHENTICATOR_MAX_REAUTH_PERIOD 86400
#elif (AUTHENTICATOR_MAX_REAUTH_PERIOD < AUTHENTICATOR_DEFAULT_REAUTH_PERIOD)
   #error AUTHENTICATOR_MAX_REAUTH_PERIOD parameter is not valid
#endif

//Maximum length of identity
#ifndef AUTHENTICATOR_MAX_ID_LEN
   #define AUTHENTICATOR_MAX_ID_LEN 64
#elif (AUTHENTICATOR_MAX_ID_LEN < 1)
   #error AUTHENTICATOR_MAX_ID_LEN parameter is not valid
#endif

//Maximum length of State attribute
#ifndef AUTHENTICATOR_MAX_STATE_SIZE
   #define AUTHENTICATOR_MAX_STATE_SIZE 64
#elif (AUTHENTICATOR_MAX_STATE_SIZE < 1)
   #error AUTHENTICATOR_MAX_STATE_SIZE parameter is not valid
#endif

//Method timeout
#ifndef AUTHENTICATOR_DEFAULT_METHOD_TIMEOUT
   #define AUTHENTICATOR_DEFAULT_METHOD_TIMEOUT 5
#elif (AUTHENTICATOR_DEFAULT_METHOD_TIMEOUT < 0)
   #error AUTHENTICATOR_DEFAULT_METHOD_TIMEOUT parameter is not valid
#endif

//Maximum number of retransmissions of RADIUS requests
#ifndef AUTHENTICATOR_MAX_RADIUS_RETRANS
   #define AUTHENTICATOR_MAX_RADIUS_RETRANS 4
#elif (AUTHENTICATOR_MAX_RADIUS_RETRANS < 0)
   #error AUTHENTICATOR_MAX_RADIUS_RETRANS parameter is not valid
#endif

//RADIUS response timeout
#ifndef AUTHENTICATOR_RADIUS_TIMEOUT
   #define AUTHENTICATOR_RADIUS_TIMEOUT 5
#elif (AUTHENTICATOR_RADIUS_TIMEOUT < 0)
   #error AUTHENTICATOR_RADIUS_TIMEOUT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Session terminate cause
 **/

typedef enum
{
   AUTHENTICATOR_TERMINATE_CAUSE_NOT_TERMINATED_YET        = 0,
   AUTHENTICATOR_TERMINATE_CAUSE_SUPPLICANT_LOGOFF         = 1,
   AUTHENTICATOR_TERMINATE_CAUSE_PORT_FAILURE              = 2,
   AUTHENTICATOR_TERMINATE_CAUSE_SUPPLICANT_RESTART        = 3,
   AUTHENTICATOR_TERMINATE_CAUSE_REAUTH_FAILED             = 4,
   AUTHENTICATOR_TERMINATE_CAUSE_AUTH_CONTROL_FORCE_UNAUTH = 5,
   AUTHENTICATOR_TERMINATE_CAUSE_PORT_REINIT               = 6,
   AUTHENTICATOR_TERMINATE_CAUSE_PORT_ADMIN_DISABLED       = 7
} AuthenticatorTerminateCause;


/**
 * @brief Authenticator PAE state change callback function
 **/

typedef void (*AuthenticatorPaeStateChangeCallback)(AuthenticatorPort *port,
   AuthenticatorPaeState state);


/**
 * @brief Backend authentication state change callback function
 **/

typedef void (*AuthenticatorBackendStateChangeCallback)(AuthenticatorPort *port,
   AuthenticatorBackendState state);


/**
 * @brief Reauthentication timer state change callback function
 **/

typedef void (*AuthenticatorReauthTimerStateChangeCallback)(AuthenticatorPort *port,
   AuthenticatorReauthTimerState state);


/**
 * @brief EAP full authenticator state change callback function
 **/

typedef void (*EapFullAuthStateChangeCallback)(AuthenticatorPort *port,
   EapFullAuthState state);


/**
 * @brief Tick callback function
 **/

typedef void (*AuthenticatorTickCallback)(AuthenticatorContext *context);


/**
 * @brief Statistics information
 **/

typedef struct
{
   uint32_t eapolFramesRx;
   uint32_t eapolFramesTx;
   uint32_t eapolStartFramesRx;
   uint32_t eapolLogoffFramesRx;
   uint32_t eapolRespIdFramesRx;
   uint32_t eapolRespFramesRx;
   uint32_t eapolReqIdFramesTx;
   uint32_t eapolReqFramesTx;
   uint32_t invalidEapolFramesRx;
   uint32_t eapLengthErrorFramesRx;
   uint32_t lastEapolFrameVersion;
} AuthenticatorStats;


/**
 * @brief Session statistics information
 **/

typedef struct
{
   uint64_t sessionOctetsRx;
   uint64_t sessionOctetsTx;
   uint32_t sessionFramesRx;
   uint32_t sessionFramesTx;
   uint32_t sessionTime;
   uint_t sessionTerminateCause;
} AuthenticatorSessionStats;


/**
 * @brief Port context
 **/

struct _AuthenticatorPort
{
   AuthenticatorContext *context;                     ///<802.1X authenticator context
   uint8_t portIndex;                                 ///<Port index
   MacAddr macAddr;                                   ///<MAC address of the port

   AuthenticatorPaeState authPaeState;                ///<Authenticator PAE state
   AuthenticatorBackendState authBackendState;        ///<Backend authentication state
   AuthenticatorReauthTimerState reauthTimerState;    ///<Reauthentication timer state

   uint_t aWhile;                                     ///<Timer used by the backend authentication state machine (8.2.2.1 a)
   uint_t quietWhile;                                 ///<Timer used by the authenticator PAE state machine (8.2.2.1 d)
   uint_t reAuthWhen;                                 ///<Timer used to determine when reauthentication takes place (8.2.2.1 e)

   bool_t authAbort;                                  ///<Abort authentication procedure (8.2.2.2 a)
   bool_t authFail;                                   ///<Authentication process has failed (8.2.2.2 b)
   AuthenticatorPortStatus authPortStatus;            ///<Current authorization state of the authenticator PAE state machine (8.2.2.2 c)
   bool_t authStart;                                  ///Start authentication procedure (8.2.2.2 d)
   bool_t authTimeout;                                ///<Failed to obtain a response from the supplicant(8.2.2.2 e)
   bool_t authSuccess;                                ///<Successful authentication process (8.2.2.2 f)
   bool_t eapFail;                                    ///<The authentication has failed (8.2.2.2 g)
   bool_t eapolEap;                                   ///<EAPOL PDU carrying a packet Type of EAP-Packet is received (8.2.2.2 h)
   bool_t eapSuccess;                                 ///<The authentication process succeeds (8.2.2.2 i)
   bool_t eapTimeout;                                 ///<The supplicant is not responding to requests (8.2.2.2 j)

   bool_t initialize;                                 ///<Forces all EAPOL state machines to their initial state (8.2.2.2 k)
   bool_t keyDone;                                    ///<This variable is set by the key machine (8.2.2.2 m)
   bool_t keyRun;                                     ///<Run transmit key machine (8.2.2.2 n)
   AuthenticatorPortMode portControl;                 ///<Port control (8.2.2.2 p)
   bool_t portEnabled;                                ///<Operational state of the port (8.2.2.2 q)
   bool_t portValid;                                  ///<The value of this variable is set externally (8.2.2.2 s)
   bool_t reAuthenticate;                             ///<The reAuthWhen timer has expired (8.2.2.2 t)

   bool_t eapolLogoff;                                ///<EAPOL-Logoff received (8.2.4.1.1 a)
   bool_t eapolStart;                                 ///<EAPOL-Start received (8.2.4.1.1 b)
   bool_t eapRestart;                                 ///<Restart Authenticator state machine (8.2.4.1.1 d)
   AuthenticatorPortMode portMode;                    ///<Port mode (8.2.4.1.1 e)
   uint_t reAuthCount;                                ///<Number of times the CONNECTING state is re-entered (8.2.4.1.1 f)

   uint_t quietPeriod;                                ///<Initialization value used for the quietWhile timer (8.2.4.1.2 a)
   uint_t reAuthMax;                                  ///<Maximum number of reauthentication attempts (8.2.4.1.2 b)

   bool_t keyTxEnabled;                               ///<Current value of the KeyTransmissionEnabled parameter (8.2.6.1.2)

   uint_t reAuthPeriod;                               ///<Number of seconds between periodic reauthentication (8.2.8.1 a)
   bool_t reAuthEnabled;                              ///<Enable or disable reauthentication (8.2.8.1 b)

   bool_t eapNoReq;                                   ///<No EAP frame to be sent to the supplicant (8.2.9.1.1 a)
   bool_t eapReq;                                     ///<An EAP frame to be sent to the supplicant (8.2.9.1.1 b)
   bool_t eapResp;                                    ///<A new EAP frame available for the higher layer to process (8.2.9.1.1 c)

   uint_t serverTimeout;                              ///<Initialization value used for the aWhile timer (8.2.9.1.2 a)

   EapFullAuthState eapFullAuthState;                 ///<EAP full authenticator state

   const uint8_t *eapRespData;                        ///<The EAP packet to be processed (5.1.1)
   size_t eapRespDataLen;                             ///<Length of the EAP response
   uint_t retransWhile;                               ///<Timer (5.1.1)

   uint8_t *eapReqData;                               ///<The actual EAP request to be sent (5.1.2)
   size_t eapReqDataLen;                              ///<Length of the EAP request
   uint8_t *eapKeyData;                               ///<EAP key (5.1.2)
   bool_t eapKeyAvailable;                            ///<Keying material is available (5.1.2)

   EapMethodType currentMethod;                       ///<Current method (5.3.1)
   uint_t currentId;                                  ///<Identifier value of the currently outstanding EAP request (5.3.1)
   EapMethodState methodState;                        ///<Method state (5.3.1)
   uint_t retransCount;                               ///<Current number of retransmissions (5.3.1)
   uint8_t *lastReqData;                              ///<EAP packet containing the last sent request (5.3.1)
   size_t lastReqDataLen;                             ///<Length of the last EAP request
   uint_t methodTimeout;                              ///<Method-provided hint for suitable retransmission timeout (5.3.1)

   bool_t rxResp;                                     ///<The current received packet is an EAP response (5.3.2)
   uint_t respId;                                     ///<Identifier from the current EAP response (5.3.2)
   EapMethodType respMethod;                          ///<Method type of the current EAP response (5.3.2)
   bool_t ignore;                                     ///<The method has decided to drop the current packet (5.3.2)
   EapDecision decision;                              ///<Decision (5.3.2)

   bool_t aaaEapReq;                                  ///<A new EAP request is ready to be sent (6.1.2)
   bool_t aaaEapNoReq;                                ///<No new request to send (6.1.2)
   bool_t aaaSuccess;                                 ///<The state machine has reached the SUCCESS state (6.1.2)
   bool_t aaaFail;                                    ///<The state machine has reached the FAILURE state (6.1.2)
   uint8_t *aaaEapReqData;                            ///<The actual EAP request to be sent (6.1.2)
   size_t aaaEapReqDataLen;                           ///<Length of the EAP request
   uint8_t *aaaEapKeyData;                            ///<EAP key (6.1.2)
   bool_t aaaEapKeyAvailable;                         ///<Keying material is available (6.1.2)
   uint_t aaaMethodTimeout;                           ///<Method-provided hint for suitable retransmission timeout (6.1.2)

   bool_t aaaEapResp;                                 ///<An EAP response is available for processing by the AAA server (7.1.2)
   const uint8_t *aaaEapRespData;                     ///<The EAP packet to be processed (5.1.2)
   size_t aaaEapRespDataLen;                          ///<Length of the EAP response
   char_t aaaIdentity[AUTHENTICATOR_MAX_ID_LEN + 1];  ///<Identity (5.1.2)

   uint_t maxRetrans;                                 ///<Maximum number of retransmissions before aborting (5.1.3)

   bool_t aaaTimeout;                                 ///<No response from the AAA layer (7.1.2)

   uint8_t aaaReqId;                                  ///<Identifier value of the currently outstanding RADIUS request
   uint8_t *aaaReqData;                               ///<RADIUS request
   size_t aaaReqDataLen;                              ///<Length of the RADIUS request
   uint_t aaaRetransTimer;                            ///<RADIUS retransmission timer
   uint_t aaaRetransCount;                            ///<Current number of retransmissions or RADIUS requests
   uint8_t reqAuthenticator[16];                      ///<Request Authenticator field
   uint8_t serverState[AUTHENTICATOR_MAX_STATE_SIZE]; ///<State attribute received from the server
   size_t serverStateLen;                             ///<Length of the state attribute, in byte
   MacAddr supplicantMacAddr;                         ///<Supplicant's MAC address

   uint8_t eapTxBuffer[AUTHENTICATOR_TX_BUFFER_SIZE]; ///<Transmission buffer for EAP requests
   uint8_t aaaTxBuffer[AUTHENTICATOR_TX_BUFFER_SIZE]; ///<Transmission buffer for RADIUS requests

   AuthenticatorStats stats;                          ///<Statistics information
   AuthenticatorSessionStats sessionStats;            ///<Session statistics information
};


/**
 * @brief 802.1X authenticator settings
 **/

typedef struct
{
   OsTaskParameters task;                                                      ///<Task parameters
   NetInterface *interface;                                                    ///<Underlying network interface
   uint_t numPorts;                                                            ///<Number of ports
   AuthenticatorPort *ports;                                                   ///<Ports
   NetInterface *serverInterface;                                              ///<RADIUS server interface
   uint_t serverPortIndex;                                                     ///<Switch port used to reach the RADIUS server
   IpAddr serverIpAddr;                                                        ///<RADIUS server's IP address
   uint16_t serverPort;                                                        ///<RADIUS server's port
   const PrngAlgo *prngAlgo;                                                   ///<Pseudo-random number generator to be used
   void *prngContext;                                                          ///<Pseudo-random number generator context
   AuthenticatorPaeStateChangeCallback paeStateChangeCallback;                 ///<Authenticator PAE state change callback function
   AuthenticatorBackendStateChangeCallback backendStateChangeCallback;         ///<Backend authentication state change callback function
   AuthenticatorReauthTimerStateChangeCallback reauthTimerStateChangeCallback; ///<Reauthentication timer state change callback function
   EapFullAuthStateChangeCallback eapFullAuthStateChangeCallback;              ///<EAP full authenticator state change callback function
   AuthenticatorTickCallback tickCallback;                                     ///<Tick callback function
} AuthenticatorSettings;


/**
 * @brief 802.1X authenticator context
 **/

struct _AuthenticatorContext
{
   bool_t running;                                      ///<Operational state of the authenticator
   bool_t stop;                                         ///<Stop request
   OsMutex mutex;                                       ///<Mutex preventing simultaneous access to 802.1X authenticator context
   OsEvent event;                                       ///<Event object used to poll the sockets
   OsTaskParameters taskParams;                         ///<Task parameters
   OsTaskId taskId;                                     ///<Task identifier
   NetContext *netContext;                              ///<TCP/IP stack context
   NetInterface *interface;                             ///<Underlying network interface
   uint_t numPorts;                                     ///<Number of ports
   AuthenticatorPort *ports;                            ///<Ports
   NetInterface *serverInterface;                       ///<RADIUS server interface
   uint_t serverPortIndex;                              ///<Switch port used to reach the RADIUS server
   IpAddr serverIpAddr;                                 ///<RADIUS server's IP address
   uint16_t serverPort;                                 ///<RADIUS server's port
   uint8_t serverKey[AUTHENTICATOR_MAX_SERVER_KEY_LEN]; ///<RADIUS server's key
   size_t serverKeyLen;                                 ///<Length of the RADIUS server's key, in bytes
   const PrngAlgo *prngAlgo;                            ///<Pseudo-random number generator to be used
   void *prngContext;                                   ///<Pseudo-random number generator context
   Socket *peerSocket;                                  ///<Raw socket used to send/receive EAP packets
   Socket *serverSocket;                                ///<UDP socket used to send/receive RADIUS packets
   AuthenticatorPaeStateChangeCallback paeStateChangeCallback;                 ///<Authenticator PAE state change callback function
   AuthenticatorBackendStateChangeCallback backendStateChangeCallback;         ///<Backend authentication state change callback function
   AuthenticatorReauthTimerStateChangeCallback reauthTimerStateChangeCallback; ///<Reauthentication timer state change callback function
   EapFullAuthStateChangeCallback eapFullAuthStateChangeCallback;              ///<EAP full authenticator state change callback function
   AuthenticatorTickCallback tickCallback;              ///<Tick callback function
   systime_t timestamp;                                 ///<Timestamp to manage timeout

   uint8_t radiusId;                                    ///<RADIUS packet identifier
   bool_t busy;                                         ///<Busy flag

   uint8_t txBuffer[AUTHENTICATOR_TX_BUFFER_SIZE];      ///<Transmission buffer
   uint8_t rxBuffer[AUTHENTICATOR_RX_BUFFER_SIZE];      ///<Reception buffer
   HmacContext hmacContext;                             ///<HMAC context
};


//Authenticator related functions
void authenticatorGetDefaultSettings(AuthenticatorSettings *settings);

error_t authenticatorInit(AuthenticatorContext *context,
   const AuthenticatorSettings *settings);

error_t authenticatorSetServerAddr(AuthenticatorContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t authenticatorSetServerKey(AuthenticatorContext *context,
   const uint8_t *key, size_t keyLen);

error_t authenticatorInitPort(AuthenticatorContext *context,
   uint_t portIndex);

error_t authenticatorReauthenticate(AuthenticatorContext *context,
   uint_t portIndex);

error_t authenticatorSetPortControl(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortMode portControl);

error_t authenticatorSetQuietPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t quietPeriod);

error_t authenticatorSetServerTimeout(AuthenticatorContext *context,
   uint_t portIndex, uint_t serverTimeout);

error_t authenticatorSetReAuthEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t reAuthEnabled);

error_t authenticatorSetReAuthPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t reAuthPeriod);

error_t authenticatorGetPortControl(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortMode *portControl);

error_t authenticatorGetQuietPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t *quietPeriod);

error_t authenticatorGetServerTimeout(AuthenticatorContext *context,
   uint_t portIndex, uint_t *serverTimeout);

error_t authenticatorGetReAuthEnabled(AuthenticatorContext *context,
   uint_t portIndex, bool_t *reAuthEnabled);

error_t authenticatorGetReAuthPeriod(AuthenticatorContext *context,
   uint_t portIndex, uint_t *reAuthPeriod);

error_t authenticatorGetPortStatus(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPortStatus *portStatus);

error_t authenticatorGetPaeState(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorPaeState *paeState);

error_t authenticatorGetBackendState(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorBackendState *backendState);

error_t authenticatorGetReauthTimerState(AuthenticatorContext *context,
   uint_t portIndex, AuthenticatorReauthTimerState *reauthTimerState);

error_t authenticatorGetEapFullAuthState(AuthenticatorContext *context,
   uint_t portIndex, EapFullAuthState *eapFullAuthState);

error_t authenticatorStart(AuthenticatorContext *context);
error_t authenticatorStop(AuthenticatorContext *context);

void authenticatorTask(AuthenticatorContext *context);

void authenticatorDeinit(AuthenticatorContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
