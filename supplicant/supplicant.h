/**
 * @file supplicant.h
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
 * @version 2.6.6
 **/

#ifndef _SUPPLICANT_H
#define _SUPPLICANT_H

//Forward declaration of SupplicantContext structure
struct _SupplicantContext;
#define SupplicantContext struct _SupplicantContext

//Dependencies
#include "eap/eap.h"
#include "eap/eap_peer_fsm.h"
#include "supplicant/supplicant_pae_fsm.h"
#include "supplicant/supplicant_backend_fsm.h"

//802.1X supplicant support
#ifndef SUPPLICANT_SUPPORT
   #define SUPPLICANT_SUPPORT ENABLED
#elif (SUPPLICANT_SUPPORT != ENABLED && SUPPLICANT_SUPPORT != DISABLED)
   #error SUPPLICANT_SUPPORT parameter is not valid
#endif

//Stack size required to run the 802.1X supplicant
#ifndef SUPPLICANT_STACK_SIZE
   #define SUPPLICANT_STACK_SIZE 750
#elif (SUPPLICANT_STACK_SIZE < 1)
   #error SUPPLICANT_STACK_SIZE parameter is not valid
#endif

//Priority at which the 802.1X supplicant should run
#ifndef SUPPLICANT_PRIORITY
   #define SUPPLICANT_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//802.1X supplicant tick interval (in milliseconds)
#ifndef SUPPLICANT_TICK_INTERVAL
   #define SUPPLICANT_TICK_INTERVAL 1000
#elif (SUPPLICANT_TICK_INTERVAL < 10)
   #error SUPPLICANT_TICK_INTERVAL parameter is not valid
#endif

//Size of the transmission buffer
#ifndef SUPPLICANT_TX_BUFFER_SIZE
   #define SUPPLICANT_TX_BUFFER_SIZE 3000
#elif (SUPPLICANT_TX_BUFFER_SIZE < 1)
   #error SUPPLICANT_TX_BUFFER_SIZE parameter is not valid
#endif

//Size of the reception buffer
#ifndef SUPPLICANT_RX_BUFFER_SIZE
   #define SUPPLICANT_RX_BUFFER_SIZE 1500
#elif (SUPPLICANT_RX_BUFFER_SIZE < 1)
   #error SUPPLICANT_RX_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of user name
#ifndef SUPPLICANT_MAX_USERNAME_LEN
   #define SUPPLICANT_MAX_USERNAME_LEN 64
#elif (SUPPLICANT_MAX_USERNAME_LEN < 1)
   #error SUPPLICANT_MAX_USERNAME_LEN parameter is not valid
#endif

//Maximum length of password
#ifndef SUPPLICANT_MAX_PASSWORD_LEN
   #define SUPPLICANT_MAX_PASSWORD_LEN 64
#elif (SUPPLICANT_MAX_PASSWORD_LEN < 1)
   #error SUPPLICANT_MAX_PASSWORD_LEN parameter is not valid
#endif

//Initialization value used for the heldWhile timer
#ifndef SUPPLICANT_DEFAULT_HELD_PERIOD
   #define SUPPLICANT_DEFAULT_HELD_PERIOD 60
#elif (SUPPLICANT_DEFAULT_HELD_PERIOD < 0)
   #error SUPPLICANT_DEFAULT_HELD_PERIOD parameter is not valid
#endif

//Initialization value used for the authWhile timer
#ifndef SUPPLICANT_DEFAULT_AUTH_PERIOD
   #define SUPPLICANT_DEFAULT_AUTH_PERIOD 30
#elif (SUPPLICANT_DEFAULT_AUTH_PERIOD < 0)
   #error SUPPLICANT_DEFAULT_AUTH_PERIOD parameter is not valid
#endif

//Initialization value used for the startWhen timer
#ifndef SUPPLICANT_DEFAULT_START_PERIOD
   #define SUPPLICANT_DEFAULT_START_PERIOD 30
#elif (SUPPLICANT_DEFAULT_START_PERIOD < 0)
   #error SUPPLICANT_DEFAULT_START_PERIOD parameter is not valid
#endif

//Maximum number of successive EAPOL-Start messages
#ifndef SUPPLICANT_DEFAULT_MAX_START
   #define SUPPLICANT_DEFAULT_MAX_START 3
#elif (SUPPLICANT_DEFAULT_MAX_START < 0)
   #error SUPPLICANT_DEFAULT_MAX_START parameter is not valid
#endif

//EAP-TLS supported?
#if (EAP_TLS_SUPPORT == ENABLED)
   #include "core/crypto.h"
   #include "tls/tls.h"
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EAP-TLS supported?
#if (EAP_TLS_SUPPORT == ENABLED)

/**
 * @brief TLS negotiation initialization callback function
 **/

typedef error_t (*SupplicantTlsInitCallback)(SupplicantContext *context,
   TlsContext *tlsContext);

/**
 * @brief TLS negotiation completion callback function
 **/

typedef void (*SupplicantTlsCompleteCallback)(SupplicantContext *context,
   TlsContext *tlsContext, error_t error);

#endif


/**
 * @brief Supplicant PAE state change callback function
 **/

typedef void (*SupplicantPaeStateChangeCallback)(SupplicantContext *context,
   SupplicantPaeState state);


/**
 * @brief Supplicant backend state change callback function
 **/

typedef void (*SupplicantBackendStateChangeCallback)(SupplicantContext *context,
   SupplicantBackendState state);


/**
 * @brief EAP peer state change callback function
 **/

typedef void (*EapPeerStateChangeCallback)(SupplicantContext *context,
   EapPeerState state);


/**
 * @brief Tick callback function
 **/

typedef void (*SupplicantTickCallback)(SupplicantContext *context);


/**
 * @brief 802.1X supplicant settings
 **/

typedef struct
{
   OsTaskParameters task;                                           ///<Task parameters
   NetInterface *interface;                                         ///<Underlying network interface
   uint_t portIndex;                                                ///<Port index
#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   const PrngAlgo *prngAlgo;                                        ///<Pseudo-random number generator to be used
   void *prngContext;                                               ///<Pseudo-random number generator context
#endif
#if (EAP_TLS_SUPPORT == ENABLED)
   SupplicantTlsInitCallback tlsInitCallback;                       ///<TLS negotiation initialization callback function
   SupplicantTlsCompleteCallback tlsCompleteCallback;               ///<TLS negotiation completion callback function
#endif
   SupplicantPaeStateChangeCallback paeStateChangeCallback;         ///<Supplicant PAE state change callback function
   SupplicantBackendStateChangeCallback backendStateChangeCallback; ///<Supplicant backend state change callback function
   EapPeerStateChangeCallback eapPeerStateChangeCallback;           ///<EAP peer state change callback function
   SupplicantTickCallback tickCallback;                             ///<Tick callback function
} SupplicantSettings;


/**
 * @brief 802.1X supplicant context
 **/

struct _SupplicantContext
{
   bool_t running;                                   ///<Operational state of the supplicant
   bool_t stop;                                      ///<Stop request
   OsMutex mutex;                                    ///<Mutex preventing simultaneous access to 802.1X supplicant context
   OsEvent event;                                    ///<Event object used to poll the underlying socket
   OsTaskParameters taskParams;                      ///<Task parameters
   OsTaskId taskId;                                  ///<Task identifier
   NetContext *netContext;                           ///<TCP/IP stack context
   NetInterface *interface;                          ///<Underlying network interface
   uint_t portIndex;                                 ///<Port index
   Socket *socket;                                   ///<Underlying socket
   char_t username[SUPPLICANT_MAX_USERNAME_LEN + 1]; ///<User name
#if (EAP_MD5_SUPPORT == ENABLED || EAP_MSCHAPV2_SUPPORT == ENABLED)
   char_t password[SUPPLICANT_MAX_PASSWORD_LEN + 1]; ///<Password
#endif
#if (EAP_MD5_SUPPORT == ENABLED)
   uint8_t digest[MD5_DIGEST_SIZE];                  ///<Calculated hash value
#endif
#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   const PrngAlgo *prngAlgo;                         ///<Pseudo-random number generator to be used
   void *prngContext;                                ///<Pseudo-random number generator context
   uint8_t opcode;                                   ///<Type of EAP MS-CHAP-V2 packet
   uint8_t mschapv2Id;                               ///<MS-CHAPv2-ID field value
   uint8_t peerChallenge[16];                        ///<Peer challenge
   uint8_t authChallenge[16];                        ///<Authenticator challenge
   uint8_t ntResponse[24];                           ///<NT-Response
#endif
#if (EAP_TLS_SUPPORT == ENABLED)
   TlsContext *tlsContext;                           ///<TLS context
   TlsSessionState tlsSession;                       ///<TLS session state
   SupplicantTlsInitCallback tlsInitCallback;        ///<TLS negotiation initialization callback function
   SupplicantTlsCompleteCallback tlsCompleteCallback;               ///<TLS negotiation completion callback function
#endif
   SupplicantPaeStateChangeCallback paeStateChangeCallback;         ///<Supplicant PAE state change callback function
   SupplicantBackendStateChangeCallback backendStateChangeCallback; ///<Supplicant backend state change callback function
   EapPeerStateChangeCallback eapPeerStateChangeCallback;           ///<EAP peer state change callback function
   SupplicantTickCallback tickCallback;              ///<Tick callback function
   systime_t timestamp;                              ///<Timestamp to manage timeout

   uint8_t txBuffer[SUPPLICANT_TX_BUFFER_SIZE];      ///<Transmission buffer
   size_t txBufferWritePos;
   size_t txBufferReadPos;
   size_t txBufferLen;
   uint8_t rxBuffer[SUPPLICANT_RX_BUFFER_SIZE];      ///<Reception buffer
   size_t rxBufferPos;
   size_t rxBufferLen;

   SupplicantPaeState suppPaeState;                  ///<Supplicant PAE state
   SupplicantBackendState suppBackendState;          ///<Supplicant backend state

   uint_t authWhile;                                 ///<Timer used by the supplicant backend state machine (8.2.2.1 a)
   uint_t heldWhile;                                 ///<Timer used by the supplicant PAE state machine (8.2.2.1 c)
   uint_t startWhen;                                 ///<Timer used by the supplicant PAE state machine (8.2.2.1 f)

   bool_t eapFail;                                   ///<The authentication has failed (8.2.2.2 g)
   bool_t eapolEap;                                  ///<EAPOL PDU carrying a packet Type of EAP-Packet is received (8.2.2.2 h)
   bool_t eapSuccess;                                ///<The authentication process succeeds (8.2.2.2 i)
   bool_t initialize;                                ///<Forces all EAPOL state machines to their initial state (8.2.2.2 k)
   bool_t keyDone;                                   ///<Variable set by the key machine (8.2.2.2 m)
   bool_t keyRun;                                    ///<Variable set by the PACP machine (8.2.2.2 n)
   SupplicantPortMode portControl;                   ///<Port control (8.2.2.2 p)
   bool_t portEnabled;                               ///<Operational state of the port (8.2.2.2 q)
   bool_t portValid;                                 ///<The value of this variable is set externally (8.2.2.2 s)
   bool_t suppAbort;                                 ///<Aborts an authentication sequence (8.2.2.2 u)
   bool_t suppFail;                                  ///<Unsuccessful authentication sequence (8.2.2.2 v)
   SupplicantPortStatus suppPortStatus;              ///<Current authorization state of the supplicant PAE state machine (8.2.2.2 w)
   bool_t suppStart;                                 ///<Start an authentication sequence (8.2.2.2 x)
   bool_t suppSuccess;                               ///<Successful authentication sequence (8.2.2.2 y)
   bool_t suppTimeout;                               ///<The authentication sequence has timed out (8.2.2.2 z)

   bool_t eapRestart;                                ///<The higher layer is ready to establish an authentication session (8.2.11.1.1 a)
   bool_t logoffSent;                                ///<An EAPOL-Logoff message has been sent (8.2.11.1.1 b)
   SupplicantPortMode sPortMode;                     ///<Used to switch between the auto and non-auto modes of operation (8.2.11.1.1 c)
   uint_t startCount;                                ///<Number of EAPOL-Start messages that have been sent (8.2.11.1.1 d)
   bool_t userLogoff;                                ///<The user is logged off (8.2.11.1.1 e)

   uint_t heldPeriod;                                ///<Initialization value used for the heldWhile timer (8.2.11.1.2 a)
   uint_t startPeriod;                               ///<Initialization value used for the startWhen timer (8.2.11.1.2 b)
   uint_t maxStart;                                  ///<Maximum number of successive EAPOL-Start messages that will be sent (8.2.11.1.2 c)

   bool_t eapNoResp;                                 ///<No EAP Response for the last EAP frame delivered to EAP (8.2.12.1.1 a)
   bool_t eapReq;                                    ///<An EAP frame is available for processing by EAP (8.2.12.1.1 b)
   bool_t eapResp;                                   ///<An EAP frame available for transmission to authenticator (8.2.12.1.1 c)

   uint_t authPeriod;                                ///<Initialization value used for the authWhile timer (8.2.12.1.2 a)

   EapPeerState eapPeerState;                        ///<EAP peer state

   bool_t allowNotifications;
   const uint8_t *eapReqData;                        ///<Contents of the EAP request (4.1.1)
   size_t eapReqDataLen;                             ///<Length of the EAP request
   uint_t idleWhile;                                 ///<Timer (4.1.1)
   bool_t altAccept;                                 ///<Alternate indication of success (4.1.1)
   bool_t altReject;                                 ///<Alternate indication of failure (4.1.1)
   uint8_t *eapRespData;                             ///<EAP response to send (4.1.2)
   size_t eapRespDataLen;                            ///<Length of the EAP response
   uint8_t *eapKeyData;                              ///<EAP key (4.1.2)
   bool_t eapKeyAvailable;                           ///<Keying material is available (4.1.2)
   uint_t clientTimeout;                             ///<Time to wait for a valid request before aborting (4.1.3)

   EapMethodType selectedMethod;                     ///<The method currently in progress (4.3.1)
   EapMethodState methodState;                       ///<Method state (4.3.1)
   uint_t lastId;                                    ///<EAP identifier value of the last request (4.3.1)
   uint8_t *lastRespData;                            ///<Last EAP packet sent from the peer (4.3.1)
   size_t lastRespDataLen;                           ///<Length of the last EAP response
   EapDecision decision;                             ///<Decision (4.3.1)

   bool_t rxReq;                                     ///<The current received packet is an EAP Request (4.3.2)
   bool_t rxSuccess;                                 ///<The current received packet is an EAP Success (4.3.2)
   bool_t rxFailure;                                 ///<The current received packet is an EAP Failure (4.3.2)
   uint_t reqId;                                     ///<Identifier value associated with the current EAP request (4.3.2)
   EapMethodType reqMethod;                          ///<Method type of the current EAP request (4.3.2)
   bool_t ignore;                                    ///<Drop the current packet (4.3.2)

   bool_t allowCanned;                               ///<Allow canned EAP Success and Failure packets
   bool_t busy;                                      ///<Busy flag
};


//Supplicant related functions
void supplicantGetDefaultSettings(SupplicantSettings *settings);

error_t supplicantInit(SupplicantContext *context,
   const SupplicantSettings *settings);

error_t supplicantSetUsername(SupplicantContext *context,
   const char_t *username);

error_t supplicantSetPassword(SupplicantContext *context,
   const char_t *password);

error_t supplicantSetHeldPeriod(SupplicantContext *context, uint_t heldPeriod);
error_t supplicantSetAuthPeriod(SupplicantContext *context, uint_t authPeriod);
error_t supplicantSetStartPeriod(SupplicantContext *context, uint_t startPeriod);
error_t supplicantSetMaxStart(SupplicantContext *context, uint_t maxStart);

error_t supplicantSetClientTimeout(SupplicantContext *context,
   uint_t clientTimeout);

error_t supplicantSetPortControl(SupplicantContext *context,
   SupplicantPortMode portControl);

error_t supplicantLogOn(SupplicantContext *context);
error_t supplicantLogOff(SupplicantContext *context);

error_t supplicantStart(SupplicantContext *context);
error_t supplicantStop(SupplicantContext *context);

void supplicantTask(SupplicantContext *context);

void supplicantDeinit(SupplicantContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
