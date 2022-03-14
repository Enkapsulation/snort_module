#ifndef __HEURISTIC_MODULE_H__
#define __HEURISTIC_MODULE_H__

#include <netinet/in.h>
#include <cstdint>
#include <array>
#include <memory>
#include <string>

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
struct DangerousIPConfig
{
   std::array<int, NUM_OF_FLAGS> flags_score;
   std::array<int, NUM_OF_ATTACK> attack_score;
   std::array<int, NUM_OF_RANGE> range_score;
   std::array<int, NUM_OF_ACCESS> access_score;
   std::array<int, NUM_OF_AVAILABILITY> availability_score;
};

/* Main policy configuration */
struct HeuristicConfig
{
   double sensitivity;
   double dangerous_entropy;
   double packet_value;
   int record_number;
   std::string filename_malicious;
   std::shared_ptr<DangerousIPConfig> filename_config;
};

/*===========================[Dangerous ip]===========================*/

/* structure to hold each element from .csv file */
struct DangerousIpAddr
{
   uint8_t attack_type;
   uint8_t range;
   uint8_t access;
   uint8_t availability;
   char flag;
   double network_entropy;
   in_addr ip_addr;
   uint64_t counter;
};

// /* list of ip parse from file */
// DangerousIpAddr* dangerous_ip_record = nullptr;

/*===========================[linked list]===========================*/

/* Double linked list structure */
struct LinkedList
{
   LinkedList* next; // Previus item on the linked list
   double entropy;
   in_addr ip_addr;
   uint64_t count;
};

/* Head of linked list */
// linkedlist* headPtr = nullptr;

/*===========================[Error enum]===========================*/
enum ParseStatus
{
   STATUS_OK = 0,
   STATUS_ERROR = 1
};


#endif /* __HEURISTIC_MODULE_H__ */