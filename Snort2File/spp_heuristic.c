/*============================================================================*\
 *   
 * #1.Includes file
 * #2.Local Defines
 * #3.Local Variables
 * #4.Policy configuration 
 * 
\*============================================================================*/

/*============================================================================*\
*   Includes file
\*============================================================================*/

/*===========================Import	]===========================*/
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

/*===========================[Local	]===========================*/
#include "sf_types.h"
#include "snort_debug.h"
#include "preprocids.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

/*
 * To get alerts from preproc you
 */
#include "generators.h"
#include "event_wrapper.h"

#include "util.h"
#include "plugbase.h"
#include "parser.h"
#include "decode.h"
#include "preprocids.h"
#include "snort_debug.h"
#include "mstring.h"
#include "session_api.h"
#include "sf_ip.h"

/*===========================[Preproc header	]===========================*/
#include "spp_heuristic.h"

/*============================================================================*\
* Local defines
\*============================================================================*/

/*
 * external globals for startup
 */
extern char *file_name;
extern int file_line;

#define ATTACK_TYPE_FACTOR 0.35
#define FLAG_FACTOR 0.65

/*============================================================================*\
* Policy configuration
\*============================================================================*/

static tSfPolicyUserContextId heuristic_config = NULL;  

/*============================================================================*\
* Functions prototypes
\*============================================================================*/
/* Function to parse conf file and init Detection rules process -> global */
static void HeuristicParseGlobalArgs(HeuristicConfig*, unsigned char*);
static void HeuristicDetectionGlobalInit(SnortConfig*, unsigned char*);

/* Function to parse conf file and init Detection rules process -> engine */
static void ParseHeuristicFlagConf(DangerousIPConfig* filename, unsigned char* args);
static void HeuristicFlagConfigInit(SnortConfig*, unsigned char*);

/* Set default value */
static void HeuristicDefaultValue();

/* Dynamic process */ 
static void HeuristicDetectionProcess(Packet*);

/* Sub detection process */ 
static void HeuristicSaveAnomaly(char* filename, char* infected, char* malicious, char flag, char* attack_type);

/* Show global config  */
static void HeuristicPrintConfig(HeuristicConfig*);
static void HeuristicPrintDangerousIPConfig(HeuristicConfig*);

/* Memory menegment policy config function */
static void HeursiticCleanExit(int, void* );
static void HeuristicFreeConfig(tSfPolicyUserContextId);
static int HeuristicFreeConfigPolicy(tSfPolicyUserContextId, tSfPolicyId, void*);

#ifdef SNORT_RELOAD
static void HerusiticDetectionReload(struct _SnortConfig*, char*, void**);
static void* HerusiticDetectionReloadSwap(struct _SnortConfig*, void*);
static void HeuristicReloadSwapFree(void* );
static void HeuristicDetectionIPDetectionReload(SnortConfig*, unsigned char*, void**);
#endif /* SNORT RELOAD */

/*============================================================================*\
* Functions needed for the proper operation of the snort
\*============================================================================*/

/****************************************************************************** 
 * 
 *  @Function: Setup_Heuristic()
 * 
 *  @breif: Registers the preprocessor keyword and initialization
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 * 
 *  @param none
 *  
 *  @return none
*/
void Setup_Heuristic(void)
{
#ifndef SNORT_RELOAD
   RegisterPreprocessor("heuristic", HeuristicDetectionGlobalInit);
   RegisterPreprocessor("heuristic_flag_conf", HeuristicFlagConfigInit);
#else
   RegisterPreprocessor("heuristic", HeuristicDetectionGlobalInit, HerusiticDetectionReload, NULL,
                        HerusiticDetectionReloadSwap, HeuristicReloadSwapFree);
   RegisterPreprocessor("heuristic_flag_conf",HeuristicFlagConfigInit, 
                        HeuristicDetectionIPDetectionReload, NULL, NULL, NULL);
#endif

   DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Preprocessor: Heuristic is setup\n"););
}

/*============================================================================*\
* Global configuration 
\*============================================================================*/

/******************************************************************************
 *  
 *  @Function:    HeuristicDetectionGlobalInit()
 * 
 *  @breif:       Calls the argument parsing function, performs final setup on data
 *                structs, links the preproc function into the function list.
 * 
 *  @param args - ptr to argument strings
 *  @param sc   - ptr to Snort current policy
 *  
 *  @return     - none
*/
static void HeuristicDetectionGlobalInit(struct _SnortConfig *sc, unsigned char* args)
{
   HeuristicConfig* pCurrentPolicyConfig = NULL;
   HeuristicConfig* pDefaultPolicyConfig = NULL;
   tSfPolicyId policy_id = getParserPolicy(sc);

   DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Preprocessor: Heuristic Initialized\n"));

   /* check pointer to preprocessor config */
   if(NULL == heuristic_config)
   {
      /* Create policy */
      heuristic_config = sfPolicyConfigCreate();
      AddFuncToPreprocCleanExitList(HeursiticCleanExit, NULL, PRIORITY_LAST, PP_HEURISTIC);
   }

   sfPolicyUserPolicySet(heuristic_config, policy_id);
   pCurrentPolicyConfig = (HeuristicConfig*)sfPolicyUserDataGetDefault(heuristic_config);
   pDefaultPolicyConfig = (HeuristicConfig*)sfPolicyUserDataGetCurrent(heuristic_config);

   if((0 != policy_id) && (NULL == pDefaultPolicyConfig))
   {
      ParseError("Heuristic configuration: Must configure default policy "
                   "if other policies are to be configured.");
   }

   if(pCurrentPolicyConfig)
   {
      ParseError("Heuristic can only be configured once.\n");
   }

   pCurrentPolicyConfig = (HeuristicConfig*)SnortAlloc(sizeof(HeuristicConfig));
   if(NULL == pCurrentPolicyConfig)
   {
      ParseError("Heursitic preprocessor: memory allocate failed.\n");
   }

   sfPolicyUserDataSetCurrent(heuristic_config, pCurrentPolicyConfig);

   if(NULL == pCurrentPolicyConfig->filename_config)
   {
      pCurrentPolicyConfig->filename_config = (DangerousIPConfig*)malloc(sizeof(DangerousIPConfig));
   }

   /* Add preproc to preproc function list */
   // AddFuncToPreprocList(sc, HeuristicDetectionProcess, PRIORITY_SCANNER, PP_HEURISTIC, PROTO_BIT__ALL);
   // session_api->enable_preproc_all_ports(sc, PP_HEURISTIC, PROTO_BIT__ALL);

   /* TEST */
   AddFuncToPreprocList(sc, HeuristicDetectionProcess, PRIORITY_NETWORK, PP_HEURISTIC, PROTO_BIT__ALL);
   session_api->enable_preproc_all_ports(sc, PP_HEURISTIC, PROTO_BIT__ALL);
   /* TEST */
   
  
   /* Set default value for algorithm parameter */
   HeuristicDefaultValue(pCurrentPolicyConfig);

   /* Parse args from conf file */
   HeuristicParseGlobalArgs(pCurrentPolicyConfig, args);

   /* Read csv file */
   ReadCSV(pCurrentPolicyConfig, &dangerous_ip_record);

   /* Sort record */
   qsort(dangerous_ip_record, pCurrentPolicyConfig->record_number, sizeof(dangerous_ip_addr), compare);

   // #ifdef inet_ntoa
   // #undef inet_ntoa
   // for(int i = 0; i < pCurrentPolicyConfig->record_number; i++)
   // {
   //    LogMessage("[%d][%u]{%s}<%c>(%lf)\n", i+1, (uint32_t)dangerous_ip_record[i].ip_addr.s_addr, inet_ntoa(dangerous_ip_record[i].ip_addr), dangerous_ip_record[i].flag, dangerous_ip_record[i].network_entropy);
   // }
   // #define inet_ntoa sfip_ntoa
   // #endif /* inet_ntoa */

   // #ifdef inet_ntoa
   // #undef inet_ntoa
   // LogMessage("[%u]{%s}<%c>(%d)(%d)(%d)(%lf)\n",(uint32_t)dangerous_ip_record[0].ip_addr.s_addr, inet_ntoa(dangerous_ip_record[0].ip_addr), dangerous_ip_record[0].flag, dangerous_ip_record[0].attack_type, dangerous_ip_record[0].range, dangerous_ip_record[0].access, dangerous_ip_record[0].availability,   dangerous_ip_record[0].network_entropy);
   // #define inet_ntoa sfip_ntoa
   // #endif /* inet_ntoa */
   
   write_structure_csv(pCurrentPolicyConfig, dangerous_ip_record);

   /* Display configuration */
   HeuristicPrintConfig(pCurrentPolicyConfig); 

}


/******************************************************************************
 * heuristic_flag_conf
 *  @param config - ptr to heuristic structure with paremeters     
 *  @param args   - ptr to args with data from conf file.
 *  
 *  @return        ConfData
*/
static void HeuristicParseGlobalArgs(HeuristicConfig* config ,unsigned char* args)
{
   char **tokens;
   int preproc_settings_numbers;
   int i = 0;

   tokens = mSplit(args, " ", 13, &preproc_settings_numbers, 0);
   
   while (i < preproc_settings_numbers)
   {
      ParseStatus status = STATUS_OK;
      int increment = 1;
      char *index = tokens[i];
      char *arg = NULL;
      char *endptr;
      int32_t value = 0;
      double entval = 0.0;

      /* In case an option takes an argument */
      if ((i + 1) < preproc_settings_numbers)
      {
         arg = tokens[i + 1];
      }

      if(!strcasecmp(index,"entropy"))
      {
         if(NULL == arg)
         {
            status = STATUS_ERROR;
         }
         else
         {
            entval = strtod(arg, &endptr);
            if((errno == ERANGE) || (*endptr != '\0'))
            {
               status = STATUS_ERROR;
            }
         }

         if(STATUS_OK != status)
         {
            ParseError("Invalid value for entropy (negative value)");
            break;
         }
         else
         {
            config->dangerous_entropy = entval;
         }

         increment = 2;
      }
      else if(!strcasecmp(index,"packet_value"))
      {
         if(NULL == arg)
         {
            status = STATUS_ERROR;
         }
         else
         {
            entval = strtod(arg, &endptr);
            if((errno == ERANGE) || (*endptr != '\0'))
            {
               status = STATUS_ERROR;
            }
         }

         if(STATUS_OK != status)
         {
            ParseError("Invalid value for packet value (negative value)");
            break;
         }
         else
         {
            config->packet_value = entval;
         }

         increment = 2;
      }
      else if(!strcasecmp(index, "sensitivity"))
      {
         if(NULL == arg)
         {
            status = STATUS_ERROR;
         }
         else
         {
            entval = strtod(arg, &endptr);
            if((errno == ERANGE) || (*endptr != '\0'))
            {
               status = STATUS_ERROR;
            }
         }

         if(STATUS_OK != status)
         {
            ParseError("Invalid value for sensitivity (negative value)");
            break;
         }
         else
         {
            config->sensitivity = entval;
         }

         increment = 2;
      }
      else if(!strcasecmp(index, "filename_malicious"))
      {

         if(NULL == arg)
         {
            status = STATUS_ERROR;
         }

         if(STATUS_OK == status)
         {
            config->filename_malicious = arg;
            config->record_number = 0;
         }
         else
         {
            ParseError("Invalid value for filename which contain dangerous ip addr\n");
         } 

         increment = 2;
      }
      else
      {
         ParseError("Invalid Heuristic engine option (%s)", index);
      }
      
      i += increment;
   }

   return;
}

/*============================================================================*\
* IP address detection configuration 
\*============================================================================*/
/******************************************************************************
 *  
 *  @Function:    HeuristicFlagConfigInit()
 * 
 *  @breif:       
 *                
 * 
 *  @param config - 
 *  @param args   - 
 *  
 *  @return     - none
*/
static void HeuristicFlagConfigInit(SnortConfig* config, unsigned char* args)
{
   tSfPolicyId policy_id = getParserPolicy(config);
   HeuristicConfig *pPolicyConfig = NULL;

   if((NULL == args) || (NULL == config))
   {
      FatalError("Missings argument or config!\n");
      return;
   }

   if(NULL == heuristic_config)
   {
      ParseError("Please active heursitc before trying to use heuristic_flag_conf");
   }

   sfPolicyUserPolicySet(heuristic_config, policy_id);
   pPolicyConfig = (HeuristicConfig *)sfPolicyUserDataGetCurrent(heuristic_config);

   if (NULL == pPolicyConfig)
   {
      ParseError("Please active heursitc before trying to use heuristic_flag_conf");
	}

   if(NULL == pPolicyConfig->filename_config)
   {
      pPolicyConfig->filename_config = (DangerousIPConfig*)malloc(sizeof(DangerousIPConfig));
   }

   ParseHeuristicFlagConf(pPolicyConfig->filename_config, args);
   HeuristicPrintDangerousIPConfig(pPolicyConfig);
}

/******************************************************************************
*  @breif:        Parser to snort.conf file.
* 
*  @param pid     Policy id assigned to each file name/ plugins       
*  @param args    
*  
*  @return        ConfData
*/
static void ParseHeuristicFlagConf(DangerousIPConfig* filename_config, unsigned char* args)
{
   char **tokens;
   int preproc_settings_numbers;
   int i = 0;

   /* split red line into tokens */
   tokens = mSplit(args, " ", 0, &preproc_settings_numbers, 0);

   while (i < preproc_settings_numbers)
   {
      ParseStatus status = STATUS_OK;
      int increment = 1;
      char *index = tokens[i];
      char *arg = NULL;
      char *endptr;
      int32_t value = 0;
      int32_t value_argument = 0;

      /* In case an option takes an argument */
      if ((i + 1) < preproc_settings_numbers)
      {
         arg = tokens[i + 1];
      }

      char* flag = arg;
      char* flag_value = tokens[i + 2];

      if(!strcasecmp(index, "dangerous"))
      {
         if((NULL == flag) || (NULL == flag_value))
         {
            status = STATUS_ERROR;
         }

         value_argument = SnortStrtol(flag_value, &endptr, 10);
         if((errno == ERANGE) || (*endptr != '\0'))
         {
            status = STATUS_ERROR;
         }

         if(STATUS_OK == status)
         {
            switch (*flag)
            {
            case 'H':
               filename_config->flags_score[H_FLAGS] = value_argument;
               break;
            case 'M':
               filename_config->flags_score[M_FLAGS] = value_argument;
               break;
            case 'L':
               filename_config->flags_score[L_FLAGS] = value_argument;
               break;
            default:
               break;
            }
         }

         increment = 3;
      }
      else if(!strcasecmp(index, "attack"))
      {
         if((NULL == flag) || (NULL == flag_value))
         {
            status = STATUS_ERROR;
         }

         value_argument = SnortStrtol(flag_value, &endptr, 10);
         if((errno == ERANGE) || (*endptr != '\0'))
         {
            status = STATUS_ERROR;
         }

         if(STATUS_OK == status)
         {
            switch (*flag)
            {
            case 'D':
               filename_config->attack_score[DDOS] = value_argument;
               break;
            case 'P':
               filename_config->attack_score[PHISING] = value_argument;
               break;
            case 'M':
               filename_config->attack_score[MALWARE] = value_argument;
               break;
            case 'R':
               filename_config->attack_score[RANSOMEWARE] = value_argument;
               break;
            case 'S':
               filename_config->attack_score[DoS] = value_argument;
               break;
            case 'X':
               filename_config->attack_score[XSS] = value_argument;
               break;
            default:
               break;
            }
         }

         increment = 3;
      }
      else if(!strcasecmp(index, "range"))
      {
         if((NULL == flag) || (NULL == flag_value))
         {
            status = STATUS_ERROR;
         }

         value_argument = SnortStrtol(flag_value, &endptr, 10);
         if((errno == ERANGE) || (*endptr != '\0'))
         {
            status = STATUS_ERROR;
         }

         if(STATUS_OK == status)
         {
            switch (*flag)
            {
            case 'S':
               filename_config->range_score[SINGLE] = value_argument;
               break;
            case 'P':
               filename_config->range_score[PARTIAL] = value_argument;
               break;
            case 'C':
               filename_config->range_score[COMPLETE] = value_argument;
               break;
            default:
               break;
            }
         }

         increment = 3;
      }
      else if(!strcasecmp(index, "access"))
      {
         if((NULL == flag) || (NULL == flag_value))
         {
            status = STATUS_ERROR;
         }

         value_argument = SnortStrtol(flag_value, &endptr, 10);
         if((errno == ERANGE) || (*endptr != '\0'))
         {
            status = STATUS_ERROR;
         }

         if(STATUS_OK == status)
         {
            switch (*flag)
            {
            case 'N':
               filename_config->access_score[NONE] = value_argument;
               break;
            case 'U':
               filename_config->access_score[USER] = value_argument;
               break;
            default:
               break;
            }
         }

         increment = 3;
      }
      else if(!strcasecmp(index, "availability"))
      {
         if((NULL == flag) || (NULL == flag_value))
         {
            status = STATUS_ERROR;
         }

         value_argument = SnortStrtol(flag_value, &endptr, 10);
         if((errno == ERANGE) || (*endptr != '\0'))
         {
            status = STATUS_ERROR;
         }

         if(STATUS_OK == status)
         {
            switch (*flag)
            {
            case 'N':
               filename_config->availability_score[NONE] = value_argument;
               break;
            case 'P':
               filename_config->availability_score[PARTIAL] = value_argument;
               break;
            case 'C':
               filename_config->availability_score[COMPLETE] = value_argument;
               break;
            default:
               break;
            }
         }

         increment = 3;
      }
      else
      {
         ParseError("Invalid Heuristic IP detection option (%s)\n", index);
      }

      i += increment;

   }

   return;
}



/*============================================================================*\
* Default value
\*============================================================================*/
/******************************************************************************
 *  
 *  @Function:    HeuristicDefaultValue()
 * 
 *  @breif:       Init default value for preprocessor
 *                
 * 
 *  @param default_flags - Pointer to current policy config
 *  
 *  @return     - none
 */
static void HeuristicDefaultValue(HeuristicConfig* default_flags)
{
   /* Init default sensitivity */
   default_flags->sensitivity = 15.0;

   /* Init default entropy */
   default_flags->dangerous_entropy = 6.0;

   /* Init default packet value */
   default_flags->packet_value = 20.0;

   /* Init default score flags */
   default_flags->filename_config->flags_score[H_FLAGS] = -3;
   default_flags->filename_config->flags_score[M_FLAGS] = -2;
   default_flags->filename_config->flags_score[L_FLAGS] = -1; 

   /* Default attack score */
   default_flags->filename_config->attack_score[DDOS] = -5;
   default_flags->filename_config->attack_score[PHISING] = -5;
   default_flags->filename_config->attack_score[MALWARE] = -5;
   default_flags->filename_config->attack_score[RANSOMEWARE] = -5;
   default_flags->filename_config->attack_score[DoS] = -5;
   default_flags->filename_config->attack_score[XSS] = -5;

   /* Default range score */
   default_flags->filename_config->range_score[SINGLE] = -1;
   default_flags->filename_config->range_score[PARTIAL] = -2;
   default_flags->filename_config->range_score[COMPLETE] = -3;

   /* Default Access score */
   default_flags->filename_config->access_score[NONE] = -2;
   default_flags->filename_config->access_score[USER] = -1;

   /* Default Availability score */
   default_flags->filename_config->availability_score[NONE] = -1;
   default_flags->filename_config->availability_score[PARTIAL] = -2;
   default_flags->filename_config->availability_score[COMPLETE] = -4;
}  

/*============================================================================*\
* Print configuration
\*============================================================================*/

/******************************************************************************
 *
 * @Function: HeuristicPrintConfig()
 * 
 * @brief Print out the global runtime configuration
 *
 * @param config - ptr to global policy config with parameters 
 *
 * @return none
 */
static void HeuristicPrintConfig(HeuristicConfig *config)
{
   if(NULL == config)
   {
      LogMessage("[-]Heursitic failed: empty configuration data\n");
      return;
   }

   LogMessage("Heursitic global config:\n");
   LogMessage("    Sensitivity: %lf\n", config->sensitivity);
   LogMessage("    Dangerous entropy: %lf\n", config->dangerous_entropy);
   LogMessage("    Start packet value: %lf\n", config->packet_value);
   if(config->packet_value < config->sensitivity)
   {
      LogMessage("[WARNING] Default packet value is lover than sensitivity\n");
   }
   LogMessage("    Malicious IP filename path: %s\n", config->filename_malicious);
   LogMessage("    IP malicious record number %d\n", config->record_number);
}

/******************************************************************************
 *
 * @Function: HeuristicPrintDangerousIPConfig()
 * 
 * @brief Print out the global runtime configuration
 *
 * @param config - ptr to global policy config with parameters 
 *
 * @return none
 */
static void HeuristicPrintDangerousIPConfig(HeuristicConfig* config)
{
   if(NULL == config)
   {
      LogMessage("[-]Heursitic failed: empty configuration data\n");
      return;
   }

   LogMessage("Heursitic flag config:\n");
   LogMessage("    Dangerous value:\n");
   LogMessage("        High: %d\n",  config->filename_config->flags_score[H_FLAGS]);
   LogMessage("        Medium: %d\n",  config->filename_config->flags_score[M_FLAGS]);
   LogMessage("        Low: %d\n",  config->filename_config->flags_score[L_FLAGS]);
   LogMessage("    Attack Value:\n"); 
   LogMessage("        DDoS: %d  \n", config->filename_config->attack_score[DDOS]);
   LogMessage("        Malware: %d  \n", config->filename_config->attack_score[PHISING]);
   LogMessage("        Phising: %d  \n", config->filename_config->attack_score[MALWARE]);
   LogMessage("        Ransomware: %d  \n", config->filename_config->attack_score[RANSOMEWARE]);
   LogMessage("        DoS: %d  \n", config->filename_config->attack_score[DoS]);
   LogMessage("        XSS: %d  \n", config->filename_config->attack_score[XSS]);
   LogMessage("    Range value:\n");
   LogMessage("        Sngle: %d\n",  config->filename_config->range_score[SINGLE]);
   LogMessage("        Partial: %d\n",  config->filename_config->range_score[PARTIAL]); 
   LogMessage("        Complete: %d\n",  config->filename_config->range_score[COMPLETE]);
   LogMessage("    Access value:\n");
   LogMessage("        None: %d\n",  config->filename_config->access_score[NONE]);
   LogMessage("        User: %d\n",  config->filename_config->access_score[USER]);
   LogMessage("    Availability value:\n");
   LogMessage("        None: %d\n",  config->filename_config->availability_score[NONE]);
   LogMessage("        Partial: %d\n",  config->filename_config->availability_score[PARTIAL]); 
   LogMessage("        Complete: %d\n",  config->filename_config->availability_score[COMPLETE]);

}

/*============================================================================*\
* Detection process 
\*============================================================================*/


/******************************************************************************
 * 
 * @Function: HeuristicDetectionProcess()
 * 
 * @breif:        Perform the preprocessor's intended function.  This can be
 *                simple (statistics collection) or complex (IP defragmentation)
 *                as you like.  Try not to destroy the performance of the whole
 *                system by trying to do too much.
 * 
 * @param pkt     - pointer to the current packet data struct
 *  
 * @return        void function
 */
static void HeuristicDetectionProcess(Packet* pkt)
{
   HeuristicConfig* config = NULL;
   char src_addr[500];
   char dst_addr[500];
   int result = -1;
   double packet_probability = 0.0;

   sfPolicyUserPolicySet (heuristic_config, getNapRuntimePolicy());
   config = (HeuristicConfig*)sfPolicyUserDataGetCurrent(heuristic_config);
   
   /* Log */
   char* type_attack;

   /* transfer start packet value */
   double ranking = config->packet_value;


   if((NULL == config))
   {
      LogMessage("[ERROR] config is NULL");
      return;
   }
   else if((NULL == pkt->iph))
   {
      return;
   }
   else
   {
      if(IS_IP4(pkt))
      {  
         /* Get dst and src IP addr */
         SnortSnprintf(src_addr, 500, inet_ntoa(GET_SRC_IP(pkt)));
         SnortSnprintf(dst_addr, 500, inet_ntoa(GET_DST_IP(pkt)));

         result = binarySearch(dangerous_ip_record, 0, config->record_number - 1, GET_SRC_IPv4(pkt));

         // if(-1 == result)
         // {
         //    result = binarySearch(dangerous_ip_record, 0, config->record_number - 1, GET_DST_IPv4(pkt));
         // }
            
         if(-1 != result)
         {

            switch (dangerous_ip_record[result].attack_type)
            {
               case DDOS: 
                  type_attack = "DDoS";
                  ranking += (ATTACK_TYPE_FACTOR * (config->filename_config->attack_score[DDOS]));
                  break;
               case PHISING: 
                  type_attack = "Phising";
                  ranking += (ATTACK_TYPE_FACTOR * (config->filename_config->attack_score[PHISING]));
                  break;
               case MALWARE: 
                  type_attack = "Malware";
                  ranking += (ATTACK_TYPE_FACTOR * (config->filename_config->attack_score[MALWARE]));
                  break;
               case RANSOMEWARE: 
                  type_attack = "Ransomware";
                  ranking += (ATTACK_TYPE_FACTOR * (config->filename_config->attack_score[RANSOMEWARE])); 
                  break;
               case DoS: 
                  type_attack = "DoS";
                  ranking += (ATTACK_TYPE_FACTOR * (config->filename_config->attack_score[DoS]));
                  break;
               case XSS:   
                  type_attack = "XSS";
                  ranking += (ATTACK_TYPE_FACTOR * (config->filename_config->attack_score[XSS])); 
                  break;
               default: break;
            }

            switch (dangerous_ip_record[result].flag)
            {
               case 'H':
                  ranking += (FLAG_FACTOR * (config->filename_config->flags_score[H_FLAGS]));
                  break;
               case 'M':
                  ranking += (FLAG_FACTOR * (config->filename_config->flags_score[M_FLAGS]));
                  break;  
               case 'L':
                  ranking += (FLAG_FACTOR * (config->filename_config->flags_score[L_FLAGS]));
                  break;    
               default: break;
            }

            switch (dangerous_ip_record[result].range)
            {
               case SINGLE:
                  ranking += config->filename_config->range_score[SINGLE];
                  break;
               case PARTIAL:
                  ranking += config->filename_config->range_score[PARTIAL];
                  break;  
               case COMPLETE:
                  ranking += config->filename_config->range_score[COMPLETE];
                  break;    
               default: break;
            }

            switch (dangerous_ip_record[result].access)
            {
               case NONE:
                  ranking += config->filename_config->access_score[NONE];
                  break;
               case USER:
                  ranking += config->filename_config->access_score[USER];
                  break;     
               default: break;
            }

            switch (dangerous_ip_record[result].availability)
            {
               case SINGLE:
                  ranking += config->filename_config->availability_score[NONE];
                  break;
               case PARTIAL:
                  ranking += config->filename_config->availability_score[PARTIAL];
                  break;  
               case COMPLETE:
                  ranking += config->filename_config->availability_score[COMPLETE];
                  break;    
               default: break;
            }
            
            /* Probability */
            dangerous_ip_record[result].counter += 1;
            packet_probability = ((double)(dangerous_ip_record[result].counter)/((double)pc.total_from_daq));
            dangerous_ip_record[result].network_entropy = ENTROPY(packet_probability);

            /* Entoropy */
            ranking -= (0.5 * (dangerous_ip_record[result].network_entropy));

            if((config->sensitivity > ranking) || (config->dangerous_entropy < dangerous_ip_record[result].network_entropy))
            {
               LogMessage("[%d][%d][FLOW]%s->%s, [ATTACK]:%s, [DANGEROUS]%c, [VALUE]%lf, [ENTROPY]:%lf\n", pc.total_from_daq, pc.ip,  src_addr, dst_addr, type_attack, dangerous_ip_record[result].flag, ranking, dangerous_ip_record[result].network_entropy);
            }
         }
      }
   }

   /* co 1000 pakietów aktualizuj raporty */
   if((0 == pc.total_from_daq % 1000))
   {
      LogMessage("[SAVE]\n");
      write_structure_csv(config, dangerous_ip_record);
   }
}

/*============================================================================*\
* Double Linked List implementation
\*============================================================================*/

/****************************************************************************** 
 * 
 *  @Function: PushElement()
 * 
 *  @breif: 
 * 
 *  @param element - pointer to linked list element
 *  @param ranking - ranking of the analyzed packet
 *  
 *  @return none
*/
void PushElement(linkedlist** element, struct in_addr addr)
{
   /* 1. allocate node */
   linkedlist* new_node = (linkedlist*)malloc(sizeof(linkedlist)); 

   /* 2. put in the data  */
   new_node->ip_addr = addr;
   new_node->count = 1;
   new_node->entropy = NO_SCORE;

   /* 3. Make next of new node as head and previous as NULL */
   new_node->next = (*element); 
      
   /* 5. move the head to point to the new node */
   (*element) = new_node; 
}

/*============================================================================*\
* CSV API Implementation
\*============================================================================*/

/****************************************************************************** 
 * 
 *  @Function: ReadCSV()
 * 
 *  @breif: function to read csv file
 * 
 *  @param file_data - pointer to HeuristicConfig structer with file name
 *  @param ip_ranking - pointer to array of structure
 *  
 *  @return none
*/
void ReadCSV(HeuristicConfig* file_data, dangerous_ip_addr** ip_ranking)
{
   FILE* fd = fopen(file_data->filename_malicious, "r");
   char line[50];
   int j = 0;
   int i = 0;
   char* token;
   double ent;
   char* endptr;
   dangerous_ip_addr* tmp_ip_ranking = NULL;

   /* Pętla do zliczenia ilości wierszy */
   for(char c = getc(fd); EOF != c; c = getc(fd))
   {
      if('\n' == c)
      {
         j++;
      }
   }

   /* długość tablicy */
   file_data->record_number = j;

   /* alokacja pamięci na sparsowane dane */
   tmp_ip_ranking = (dangerous_ip_addr*)malloc(j * sizeof(dangerous_ip_addr));

   /* przewijanie pliku do początku */
   rewind(fd);

   /* pobieranie i przypisanie danych z pliku */
   while(fgets(line, sizeof(line), fd))
   {
      /* Read malicious IP addr */
      struct in_addr IP_struct;
      token = strtok(line, ",");
      inet_aton(token, &IP_struct);
      tmp_ip_ranking[i].ip_addr = IP_struct;

      /* Read flag */
      token = strtok(NULL, ",");
      tmp_ip_ranking[i].flag = token[0];

      /* Read probably attack */
      token = strtok(NULL, ",");
      switch(*token)
      {
         case 'D': tmp_ip_ranking[i].attack_type = DDOS; break;
         case 'P': tmp_ip_ranking[i].attack_type = PHISING; break;
         case 'M': tmp_ip_ranking[i].attack_type = MALWARE; break;
         case 'R': tmp_ip_ranking[i].attack_type = RANSOMEWARE; break;
         case 'S': tmp_ip_ranking[i].attack_type = DoS; break;
         case 'X': tmp_ip_ranking[i].attack_type = XSS; break;
         default: break;
      }

      /* Read range */
      token = strtok(NULL, ",");
      switch(*token)
      {
         case 'S': tmp_ip_ranking[i].range = SINGLE; break;
         case 'P': tmp_ip_ranking[i].range = PARTIAL; break;
         case 'C': tmp_ip_ranking[i].range = COMPLETE; break;
         default: break;
      }

      /* Read access */
      token = strtok(NULL, ",");
      switch(*token)
      {
         case 'N': tmp_ip_ranking[i].access = NONE; break;
         case 'U': tmp_ip_ranking[i].access = USER; break;
         default: break;
      }

      /* Read availability */
      token = strtok(NULL, ",");
      switch(*token)
      {
         case 'N': tmp_ip_ranking[i].availability = NONE; break;
         case 'P': tmp_ip_ranking[i].availability = PARTIAL; break;
         case 'C': tmp_ip_ranking[i].availability = COMPLETE; break;
         default: break;
      }

      /* Read counter */
      token = strtok(NULL, ",");
      tmp_ip_ranking[i].counter = strtol(token, &endptr, 0);

      /* Read entropy */
      token = strtok(NULL, "\n");
      tmp_ip_ranking[i].network_entropy = strtod(token, endptr);

      i++;
   }

   /* Move data to main array */
   *ip_ranking = tmp_ip_ranking;

   /* closed file descriptor*/
   fclose(fd); 
}

// /****************************************************************************** 
//  * 
//  *  @Function: ReadCSV()
//  * 
//  *  @breif: 
//  * 
//  *  @param filename - 
//  *  @param ip_ranking - 
//  *  @param array_length -
//  *  
//  *  @return none
// */
// void ReadCSV_network_traffic(DangerousIPConfig* filename, network_traffic_element** ip_ranking)
// {
//    FILE* fd = fopen(filename->filename_infected, "r");
//    char line[50];
//    int j = 0;
//    int i = 0;
//    char* token;
//    double ent;
//    char* endptr;
//    network_traffic_element* tmp_ip_ranking = NULL;

//    /* Pętla do zliczenia ilości wierszy */
//    for(char c = getc(fd); EOF != c; c = getc(fd))
//    {
//       if('\n' == c)
//       {
//          j++;
//       }
//    }

//    /* długość tablicy */
//    filename->infected_row_number = j;

//    /* alokacja pamięci na sparsowane dane */
//    tmp_ip_ranking = (network_traffic_element*)malloc(500 * sizeof(network_traffic_element));

//    /* przewijanie pliku do początku */
//    rewind(fd);

//    /* pobieranie i przypisanie danych z pliku */
//    while(fgets(line, sizeof(line), fd))
//    {
//       /* Read malicious IP addr */
//       struct in_addr IP_struct;
//       token = strtok(line, ",");
//       inet_aton(token, &IP_struct);
//       tmp_ip_ranking[i].ip_addr = IP_struct;

//       /* Read counter */
//       token = strtok(NULL, ",");
//       tmp_ip_ranking[i].counter = strtol(token, &endptr, 0);

//       /* Read entropy */
//       token = strtok(NULL, "\n");
//       tmp_ip_ranking[i].entropy = strtod(token, endptr);

//       i++;
//    }

//    /* Move data to main array */
//    *ip_ranking = tmp_ip_ranking;

//    /* closed file descriptor*/
//    fclose(fd); 
// }

/****************************************************************************** 
 * 
 *  @Function: write_csv()
 * 
 *  @breif: 
 * 
 *  @param arr - 
 *  @param first_index_element - 
 *  @param last_index_element -
 *  @param value_to_find -
 *  
 *  @return none
*/
void write_csv(char* filename, char* ip_addr, int counter, double entropy)
{
   FILE* fd = fopen(filename, "a+");
   char line[100]; // Linia jest do trzymania aktualnej linii. Nie potrzebuje dużego rozmiaru
   int j = 0;
   int i = 0;
   char* token;

   /* pobieranie i przypisanie danych z pliku */
   fprintf(fd, "%s,", ip_addr);
   fprintf(fd, "%d,", counter);
   fprintf(fd, "%f\n", entropy);

   /* zamknięcie deskryptora pliku */
   fclose(fd); 
}

/****************************************************************************** 
 * 
 *  @Function: write_structure_csv()
 * 
 *  @breif: 
 * 
 *  @param arr - 
 *  @param first_index_element - 
 *  @param last_index_element -
 *  @param value_to_find -
 *  
 *  @return none
*/
void write_structure_csv(HeuristicConfig* file, dangerous_ip_addr* infected_ip_addr)
{
   FILE* fd = fopen(file->filename_malicious, "w");
   int j = 0;
   int i = 0;
   char* token;
   char bufor_ch;

   /* pobieranie i przypisanie danych z pliku */
   for(int i = 0; i < file->record_number; i++)
   {
      #ifdef inet_ntoa
      #undef inet_ntoa
      token = inet_ntoa(infected_ip_addr[i].ip_addr);
      fprintf(fd, "%s,", token);
      #define inet_ntoa sfip_ntoa
      #endif /* inet_ntoa */

      switch (infected_ip_addr[i].flag)
      {
         case 'H': bufor_ch = 'H'; break;
         case 'M': bufor_ch = 'M'; break;
         case 'L': bufor_ch = 'L'; break;   
         default: break;
      }
      fprintf(fd, "%c,", bufor_ch);

      switch (infected_ip_addr[i].attack_type)
      {
         case 0: bufor_ch = 'D'; break;
         case 1: bufor_ch = 'P'; break;
         case 2: bufor_ch = 'M'; break;
         case 3: bufor_ch = 'R'; break;
         case 4: bufor_ch = 'S'; break;
         case 5: bufor_ch = 'X'; break;
         default: break;
      }
      fprintf(fd, "%c,", bufor_ch);

      switch (infected_ip_addr[i].range)
      {
         case 0: bufor_ch = 'S'; break;
         case 1: bufor_ch = 'P'; break;
         case 2: bufor_ch = 'C'; break;   
         default: break;
      }
      fprintf(fd, "%c,", bufor_ch);

      switch (infected_ip_addr[i].access)
      {
         case 0: bufor_ch = 'N'; break;
         case 1: bufor_ch = 'U'; break;  
         default: break;
      }
      fprintf(fd, "%c,", bufor_ch);

      switch (infected_ip_addr[i].availability)
      {
         case 0: bufor_ch = 'N'; break;
         case 1: bufor_ch = 'P'; break;
         case 2: bufor_ch = 'C'; break;  
         default: break;
      }
      fprintf(fd, "%c,", bufor_ch);

      fprintf(fd, "%d,", infected_ip_addr[i].counter);
      fprintf(fd, "%lf\n", infected_ip_addr[i].network_entropy);
   }
   /* zamknięcie deskryptora pliku */
   fclose(fd); 
}

/*============================================================================*\
* Quick sort implementation
\*============================================================================*/
int compare (const void* a, const void* b)
{
   dangerous_ip_addr* _a = (dangerous_ip_addr *)a;
   dangerous_ip_addr* _b = (dangerous_ip_addr *)b;
   int status = 0;
   long int result = 0;

   if((uint32_t)_b->ip_addr.s_addr > (uint32_t)_a->ip_addr.s_addr) 
   {  
      result = ((uint32_t)_b->ip_addr.s_addr) - ((uint32_t)_a->ip_addr.s_addr);
      if (0 == result)
      {
         status = 0;
      }
      else if (0 < result)
      {
         status = -1;
      }
      return status;
   }
   else if((uint32_t)_b->ip_addr.s_addr < (uint32_t)_a->ip_addr.s_addr) 
   {  
      result = ((uint32_t)_a->ip_addr.s_addr) - ((uint32_t)_b->ip_addr.s_addr);
      if (0 == result)
      {
         status = 0;
      }
      else if (0 < result)
      {
         status = 1;
      }
      return status;
   }

   return status;
}

// int network_compare(const void* a, const void* b)
// {
//    network_traffic_element* _a = (network_traffic_element *)a;
//    network_traffic_element* _b = (network_traffic_element *)b;
//    int status = 0;
//    long int result = 0;

//    if((uint32_t)_b->ip_addr.s_addr > (uint32_t)_a->ip_addr.s_addr) 
//    {  
//       result = ((uint32_t)_b->ip_addr.s_addr) - ((uint32_t)_a->ip_addr.s_addr);
//       if (0 == result)
//       {
//          status = 0;
//       }
//       else if (0 < result)
//       {
//          status = 1;
//       }
//       return status;
//    }
//    else if((uint32_t)_b->ip_addr.s_addr < (uint32_t)_a->ip_addr.s_addr) 
//    {  
//       result = ((uint32_t)_a->ip_addr.s_addr) - ((uint32_t)_b->ip_addr.s_addr);
//       if (0 == result)
//       {
//          status = 0;
//       }
//       else if (0 < result)
//       {
//          status = -1;
//       }
//       return status;
//    }

//    return status;
// }

/*============================================================================*\
* Binary search 
\*============================================================================*/

/****************************************************************************** 
 * 
 *  @Function: binarySearch()
 * 
 *  @breif: 
 * 
 *  @param arr - 
 *  @param first_index_element - 
 *  @param last_index_element -
 *  @param value_to_find -
 *  
 *  @return none
*/
int binarySearch(dangerous_ip_addr* arr, int first_index_element, int last_index_element, struct in_addr src_value_to_find) 
{ 
   while (first_index_element <= last_index_element) 
   { 
      int mid = first_index_element + (last_index_element - first_index_element) / 2;

      //Check if x is present at mid 
      if ((arr[mid].ip_addr.s_addr == src_value_to_find.s_addr))
      {
         return mid;
      }
      else if ((arr[mid].ip_addr.s_addr < src_value_to_find.s_addr))
      {
         first_index_element = mid + 1;
      }
      else
      {
         last_index_element = mid - 1;
      }
   }

   return -1;
}

/****************************************************************************** 
 * 
 *  @Function: binarySearch()
 * 
 *  @breif: 
 * 
 *  @param arr - 
 *  @param first_index_element - 
 *  @param last_index_element -
 *  @param value_to_find -
 *  
 *  @return none
*/
// int NetworkBinarySearch(network_traffic_element* arr, int first_index_element, int last_index_element, struct in_addr src_value_to_find) 
// { 
//    while (first_index_element <= last_index_element) 
//    { 
//       int mid = first_index_element + (last_index_element - first_index_element) / 2;

//       //Check if x is present at mid 
//       if ((arr[mid].ip_addr.s_addr == src_value_to_find.s_addr))
//       {
//          return mid;
//       }
//       else if ((arr[mid].ip_addr.s_addr < src_value_to_find.s_addr))
//       {
//          first_index_element = mid + 1;
//       }
//       else
//       {
//          last_index_element = mid - 1;
//       }
//    }

//    return -1;
// }  

/*============================================================================*\
* Clean policy Function
\*============================================================================*/
static void HeursiticCleanExit(int signal, void* unused)
{
   HeuristicFreeConfig(heuristic_config);
   heuristic_config = NULL;
} 

static int HeuristicFreeConfigPolicy(tSfPolicyUserContextId config,tSfPolicyId policyId, void* pData )
{
   HeuristicConfig *pPolicyConfig = (HeuristicConfig *)pData;

   sfPolicyUserDataClear (config, policyId);
   free(pPolicyConfig);
   return 0;
}

static void HeuristicFreeConfig(tSfPolicyUserContextId config)
{
   if(NULL == config)
   {
      return;
   }

   sfPolicyUserDataFreeIterate (config, HeuristicFreeConfigPolicy);
   sfPolicyConfigDelete(config);
}

/*============================================================================*\
* Snort reload functions
\*============================================================================*/

#ifdef SNORT_RELOAD
/*============================[Reload	]=====================================*/
static void HerusiticDetectionReload(struct _SnortConfig* sc, char* args, void** new_config)
{
   tSfPolicyUserContextId heuristic_swap_config = (tSfPolicyUserContextId)*new_config;
   int policy_id = (int)getParserPolicy(sc);
   HeuristicConfig* pPolicyConfig;
   HeuristicConfig* config = NULL;

   /* allocate memory for config */
   if(NULL == heuristic_swap_config)
   {
      heuristic_swap_config = sfPolicyConfigCreate();
      if(NULL == heuristic_swap_config)
      {
         FatalError("Failed to allocate memory "
                                            "for Heuristic config.\n");
         return;
      }

      *new_config = (void *)heuristic_swap_config;
   }

   /* preprocessor configuration */
   sfPolicyUserPolicySet (heuristic_swap_config, policy_id);

   pPolicyConfig = (HeuristicConfig *)sfPolicyUserDataGetCurrent(heuristic_swap_config);
   if (NULL != pPolicyConfig)
   {
      FatalError("Heuristic preprocessor can only be configured once.\n");
   }

   /* allocate memory for preproc configuration */
   pPolicyConfig = (HeuristicConfig *)SnortAlloc(sizeof(HeuristicConfig));
   if(NULL == pPolicyConfig)
   {
      ParseError("Could not allocate memory for Heuristic preprocessor configuration.\n");
   }

   sfPolicyUserDataSetCurrent(heuristic_swap_config, pPolicyConfig);

   /* dodac PP_HEURISTIC do preprocids.h; poszukać po co jest PROTO_BIT__TCP, ogólnie po co addPreproc i co to robi*/
   AddFuncToPreprocList(sc, HeuristicDetectionProcess, PRIORITY_APPLICATION, PP_ALL, PROTO_BIT__TCP);

   /* Parse the heuristic arguments from snort.conf */
   HeuristicParseGlobalArgs(config, (u_char*)args);
}


/*============================[Swap	]=====================================*/
static void* HerusiticDetectionReloadSwap(SnortConfig* sc, void* swap_config)
{
   tSfPolicyUserContextId heuristic_swap_config = (tSfPolicyUserContextId)swap_config;
   tSfPolicyUserContextId old_config = heuristic_config;

   if (NULL == heuristic_swap_config)
   { 
      return NULL;
   }

   heuristic_config = heuristic_swap_config;
   heuristic_swap_config = NULL;

   if(NULL == sfPolicyUserPolicyGetActive(old_config))
   {
      /* No more outstanding configs - free the config array */
      return (void *)old_config;
   }

   return NULL;
}


/*============================[Free	]=====================================*/
static void HeuristicReloadSwapFree(void *data)
{
   if (NULL == data)
   {
      return;
   }

   HeuristicFreeConfig((tSfPolicyUserContextId)data);
}
/*============================[Reload IP	]=====================================*/
static void HeuristicDetectionIPDetectionReload(SnortConfig* config, unsigned char* args, void** new_config)
{
   tSfPolicyId policy_id = getParserPolicy(config);
   HeuristicConfig *pPolicyConfig = NULL;

   if((NULL == args) || (NULL == config))
   {
      FatalError("Missings argument or config!\n");
      return;
   }

   if(NULL == heuristic_config)
   {
      ParseError("Please active heursitc before trying to use heuristic_flag_conf");
   }

   sfPolicyUserPolicySet(heuristic_config, policy_id);
   pPolicyConfig = (HeuristicConfig *)sfPolicyUserDataGetCurrent(heuristic_config);

   if (NULL == pPolicyConfig)
   {
   ParseError("Please active heursitc before trying to use heuristic_flag_conf");
   }

   if(NULL == pPolicyConfig->filename_config)
   {
      pPolicyConfig->filename_config = (DangerousIPConfig*)malloc(sizeof(DangerousIPConfig));
   }

   ParseHeuristicFlagConf(pPolicyConfig->filename_config, args);
   ReadCSV(pPolicyConfig->filename_config, &dangerous_ip_record);
   HeuristicPrintDangerousIPConfig(pPolicyConfig);
}

#endif /* SNORT_RELOAD */

