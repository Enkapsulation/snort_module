#include <fstream>
#include <string>
#include <vector>
#include <memory>

#include "heuristic_types.hpp"

void ReadCSV(std::shared_ptr<HeuristicConfig> file_data, DangerousIpAddr** ip_ranking)
{
	std::ofstream fd;
   fd.open(file_data->filename_malicious);

   char line[50];
   int j = 0;
   int i = 0;
   char* token;
   double ent;
   char* endptr;
   DangerousIpAddr* tmp_ip_ranking = NULL;

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