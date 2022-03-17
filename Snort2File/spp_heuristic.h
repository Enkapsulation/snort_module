#ifndef __SPP_HEURISTIC_H__
#define __SPP_HEURISTIC_H__

/*============================================================================*\
* Local defines
\*============================================================================*/
#include <math.h>

/*============================================================================*\
* Local defines
\*============================================================================*/

/*===========================[DEBUG	]===========================*/
#ifdef DEBUG
#define DEBUG_HEURISTIC DEBUG_PP
#endif

/*===========================[LOGGER DEFINES	]===========================*/

#define GENERATOR_SPP_HEURISTIC 256
#define HEURISTIC_BRUTEFORECE_DETECT 1

#define HEURISTIC_DETECT_STRING "(spp_heuristic) Detect enormous anomaly"

/* Shanon entropy */
#define LOG2 0.69314718056
#define ENTROPY( prob ) ( -1 * ( log( prob ) / LOG2 ) )

/* Default value for entropy */
#define NO_SCORE ( double )-1

/* Get src/dst IPv4 addr */
#define GET_SRC_IPv4( pkt ) ( ( pkt )->iph->ip_src )
#define GET_DST_IPv4( pkt ) ( ( pkt )->iph->ip_dst )

/* Get row number */
#define GET_IN_ROW_NUMBER( config ) ( ( config )->filename_config->infected_row_number )

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
#define DDOS 0
#define PHISING 1
#define MALWARE 2
#define RANSOMEWARE 3
#define DoS 4
#define XSS 5

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
	int flags_score[ NUM_OF_FLAGS ];
	int attack_score[ NUM_OF_ATTACK ];
	int range_score[ NUM_OF_RANGE ];
	int access_score[ NUM_OF_ACCESS ];
	int availability_score[ NUM_OF_AVAILABILITY ];
} DangerousIPConfig;

/* Main policy configuration */
typedef struct _heuristicConfig
{
	double sensitivity;
	double dangerous_entropy;
	double packet_value;
	char* filename_malicious;
	int record_number;
	DangerousIPConfig* filename_config;
} HeuristicConfig;

/*===========================[Dangerous ip]===========================*/

/* structure to hold each element from .csv file */
typedef struct _dangerous_ip_addr
{
	struct in_addr ip_addr;
	char flag;
	uint8_t attack_type;
	uint8_t range;
	uint8_t access;
	uint8_t availability;
	double network_entropy;
	uint64_t counter;
} dangerous_ip_addr;

/* list of ip parse from file */
dangerous_ip_addr* dangerous_ip_record = NULL;

/*===========================[linked list]===========================*/

/* Double linked list structure */
typedef struct _linkedlist
{
	struct dlinkedlist* next; // Previus item on the linked list
	struct in_addr ip_addr;
	uint64_t count;
	double entropy;
} linkedlist;

/* Head of linked list */
linkedlist* headPtr = NULL;

/*===========================[network_traffic_element]===========================*/

// /* this structure decribe structure for infected ip addr */
// typedef struct _network_traffic_element
// {
//    struct in_addr ip_addr;
//    uint64_t counter;
//    double entropy;
//    linkedlist* connection;
// }network_traffic_element;

// /* list of ip parse from file */
// network_traffic_element* network_traffic = NULL;

/*===========================[Error enum]===========================*/
typedef enum _HeuristicParseTypes
{
	STATUS_OK	 = 0,
	STATUS_ERROR = 1
} ParseStatus;

/*============================================================================*\
* Export function
\*============================================================================*/
void Setup_Heuristic( void );

/* Double Linked List implementaion */
void PushElement( linkedlist** element, struct in_addr addr );

/* Read .csv file; find dangerous ip address */
void ReadCSV( HeuristicConfig* filename, dangerous_ip_addr** ip_ranking );
// void read_csv_network_traffic(DangerousIPConfig* filename, network_traffic_element** ip_ranking);

void write_csv( char* filename, char* ip_addr, int counter, double entropy );
void write_structure_csv( HeuristicConfig* file, dangerous_ip_addr* infected_ip_addr );

/* Binary search implementation */
int binarySearch( dangerous_ip_addr* arr,
				  int first_index_element,
				  int last_index_element,
				  struct in_addr src_value_to_find );
// int NetworkBinarySearch(network_traffic_element* arr, int first_index_element, int last_index_element, struct in_addr
// src_value_to_find);

/* Compare 2 elements for quick sort */
int compare( const void* a, const void* b );
int network_compare( const void* a, const void* b );

#endif /*  __SPP_HEURISTIC_DETECTION_H__ */