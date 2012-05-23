#ifndef _COMMAND_H
#define _COMMAND_H

#define COMMAND_DEVICE_LIST 1 /*recupere la liste des interfaces reseaux disponible pour l'ecoute*/

#define COMMAND_GET_PROTOCOL_LIST 2 /*active l'envoi d'information sur les flux que l'on voit passer*/
#define COMMAND_SELECT_CAPTURE_DEVICE 4 /*selectionne une interface d'ecoute*/
#define COMMAND_DISABLE_CAPTURE_DEVICE 5 /*deselectionne une interface d'ecoute*/
#define COMMAND_SELECT_CAPTURE_FILE 6 /*selectionne un fichier de capture*/

#define COMMAND_SET_SPEED 7 /*defini la vitesse de lecture d'un fichier de capture*/

#define COMMAND_PARSE_FILE 8 /*parse un fichier pour identifier les protocoles present*/

#define COMMAND_START_CAPTURE 9 /*demarre la capture pour un protocol et pour l'envoyer en reconstitution*/
#define COMMAND_STOP_CAPTURE 10 /*desactive une capture*/

#define COMMAND_STOP_ALL_CAPTURE 11 /*desactive l'ensemble des captures*/
#define COMMAND_LIST_FILE 12 /*liste les fichiers disponible*/
#define COMMAND_START_RECORD 13 /*commence l'enregistrement sur un fichier*/
#define COMMAND_STOP_RECORD 14 /*stop l'enregistrement sur un fichier*/

#define COMMAND_SET_BUFFER_LENGTH_PROTO_LIST 15 /* Nombre maximum d'entrée pour la liste de protocols */
#define COMMAND_CLEAR_PROTO_LIST 16 /* Effacer les entrées dans la liste de protocols */

#define COMMAND_SET_MASTER_FILTER 17 /*Definit le filtre principale sur l'interface*/
#define COMMAND_TEST_MASTER_FILTER 18 /*Definit le filtre principale sur l'interface*/

#define COMMAND_FLUSH_SEGMENT 19 /*Definit le filtre principale sur l'interface*/

#define COMMAND_STREAM_PAUSE 20
#define COMMAND_STREAM_RESUME 21
#define COMMAND_FILE_READ 22
#define COMMAND_FILE_GOTO 23

#define COMMAND_SELECT_CAPTURE_DEVICE_WITH_MONITORING 24 /*on tente de forcer le monitoring*/
#define COMMAND_GET_STATE 25

#define STATE_NO_ERROR 0
#define STATE_NO_DEVICE_SELECTED 1
#define STATE_UNKNOWN_CAPTURE_DEVICE 2
#define STATE_UNKNOWN_FILE 3
#define STATE_NOT_ALLOWED_IN_FILE_MODE 4
#define STATE_NOT_ALLOWED_IN_DEVICE_MODE 5
#define STATE_MUST_STOP_CAPTURE_BEFORE 6
#define STATE_CAPTURE_NOT_STARTED 7
#define STATE_PCAP_ERROR 8
#define STATE_FAILED_TO_RECEIVED_STRING 9
#define STATE_SERVER_ERROR 10
#define STATE_SEND_COMMAND_TO_DISPATCH_FAILED 11
#define STATE_NO_FILE_SELECTED 12
#define STATE_ARG_WRONG_OR_MISSING 13
/*#define STATE_IP_VER_MUST_BE_DEFINE_FIRST 14
#define STATE_CAN_T_MERGE_IP_VER 15
#define STATE_UNKNOWN_FILTER_PARAM 16
#define STATE_PARAM_CAN_T_APPEAR_TWICE 17*/
#define STATE_VALUE_POSITIVE_INVALID 18
#define STATE_WRONG_BPF 19
#define STATE_RECORD_ALREADY_STARTED 20
#define STATE_NOTHING_SELECTED 21
#define STATE_DATALINK_NOT_MANAGED 22
#define STATE_NO_MORE_PORT_AVAILABLE 23
#define STATE_NOT_IMPLEMENTED_YET 24
#define STATE_NOT_RUNNING 25
#define STATE_NOT_IN_PAUSE 26
#define STATE_ZERO_VALUE 27
#define STATE_ALREADY_RUNNING 28
#define STATE_INVALID_IDENTIFIER 29

#define SPEED_NORMAL 0
#define SPEED_FASTER 1
#define SPEED_SLOWER 2

#endif