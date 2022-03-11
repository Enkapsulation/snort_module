// #ifndef __HEURISTIC_H__
// #define __HEURISTIC_H__

#include <netinet/in.h>
#include <stdint.h>

#define GENERATOR_SPP_HEURISTIC 256
#define     HEURISTIC_BRUTEFORECE_DETECT 1   

#define HEURISTIC_DETECT_STRING "(spp_heuristic) Detect enormous anomaly"

/* Shanon entropy */
#define LOG2 0.69314718056
#define ENTROPY(prob) (-1*(log(prob)/LOG2))

/* Default value for entropy */
#define NO_SCORE (double)-1

/* Get row number */
#define GET_IN_ROW_NUMBER(config) ((config)->filename_config->infected_row_number)

/*  number of flag types */
#define NUM_OF_FLAGS 3
#define NUM_OF_ATTACK 6
#define NUM_OF_RANGE 3
#define NUM_OF_ACCESS 2
#define NUM_OF_AVAILABILITY 3

/* Risk flags */
#define H_FLAGS 0
#define M_FLAGS 1
#define L_FLAGS 2

/* Attack types */
#define DDOS         0
#define PHISING      1
#define MALWARE      2
#define RANSOMEWARE  3
#define DoS          4
#define XSS          5

/* range flags */
#define SINGLE 0
#define PARTIAL 1
#define COMPLETE 2

/* Access flags */
#define NONE 0
#define USER 1

/* Availability flags */
#define NONE 0
#define PARTIAL 1
#define COMPLETE 2

/*============================================================================*\
* Local variables
\*============================================================================*/

/*===========================[Heurstic structure]===========================*/

/* Structre define file config for subpreprocessor */
typedef struct _DangerousIPConfig
{
   int flags_score[NUM_OF_FLAGS];
   int attack_score[NUM_OF_ATTACK];
   int range_score[NUM_OF_RANGE];
   int access_score[NUM_OF_ACCESS];
   int availability_score[NUM_OF_AVAILABILITY];
}DangerousIPConfig;

/* Main policy configuration */
typedef struct _heuristicConfig
{
   double sensitivity {};
   double dangerous_entropy {};
   double packet_value {};
   char* filename_malicious {};
   int record_number {};
   DangerousIPConfig* filename_config {};
}HeuristicConfig, *pHeuristicConfig;

/*===========================[Dangerous ip]===========================*/

/* structure to hold each element from .csv file */
typedef struct _dangerous_ip_addr
{
   struct in_addr ip_addr {};
   char flag {};
   uint8_t attack_type {};
   uint8_t range {};
   uint8_t access {};
   uint8_t availability {};
   double network_entropy {};
   uint64_t counter {};
}dangerous_ip_addr;

/* list of ip parse from file */
dangerous_ip_addr* dangerous_ip_record = nullptr;

/*===========================[linked list]===========================*/

/* Double linked list structure */
typedef struct _linkedlist
{
   struct dlinkedlist* next; // Previus item on the linked list
   struct in_addr ip_addr;
   uint64_t count;
   double entropy;
}linkedlist;

/* Head of linked list */
linkedlist* headPtr = nullptr;

/*===========================[Error enum]===========================*/
typedef enum _HeuristicParseTypes
{
   STATUS_OK = 0,
   STATUS_ERROR = 1
}ParseStatus;


// #endif /* __HEURISTIC_H__ */