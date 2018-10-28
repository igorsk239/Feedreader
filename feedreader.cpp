/*
 * File: feeder.cpp
 * Author: Igor Ignác xignac00@fit.vutbr.cz
 * Name: ISA project
 * Created: 2018/2019
 * Faculty: Faculty of Information Technology, Brno University of Technology
*/
#include "feedreader.h"
#include <algorithm>
#include <string.h>
#include <stdio.h>
#include <string>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static const char * params[5] = {"-c", "-C", "-T", "-a", "-u"};
static const char * feedFile;
static const char * certFile;
static const char * certDir;
//static bool certFileExists = false; certDirExists = false;
static bool paramError = false;


int argExists(char *argv[])
{
  if(argv[2] != NULL)
  {
    for( unsigned int a = 0; a < sizeof(params)/sizeof(params[0]); a = a + 1 )
    {
      if(strcmp(params[a],argv[2]) == 0){paramError = false; break;}
      else  paramError = true;
    }
    if(argv[3] != NULL)
    {
      for( unsigned int a = 0; a < sizeof(params)/sizeof(params[0]); a = a + 1 )
      {
        if(strcmp(params[a],argv[3]) == 0){paramError = false; break;}
        else  paramError = true;
      }
      if(argv[4] != NULL)
      {
        for( unsigned int a = 0; a < sizeof(params)/sizeof(params[0]); a = a + 1 )
        {
          if(strcmp(params[a],argv[4]) == 0){paramError = false; break;}
          else  paramError = true;
        }
        if(argv[5] != NULL)
        {
          for( unsigned int a = 0; a < sizeof(params)/sizeof(params[0]); a = a + 1 )
          {
            if(strcmp(params[a],argv[5]) == 0){paramError = false; break;}
            else  paramError = true;
          }
        }
      }
    }
  }
  if(paramError) return ERROR_PARAMS;

  return CORRECT;
}

char* getCmdOption(char ** begin, char ** end, const std::string & option)
{
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}

int certExists(char *argv[], int argc)
{
  for(int a = 0; a < argc; a = a + 1 )
  {
    if(strcmp(argv[a], "-c") == 0)
    {
      //certFileExists = true;
      certFile = getCmdOption(argv, argv + argc, "-c");
      return CERT_FILE;
    }
    else if (strcmp(argv[a], "-C") == 0)
    {
      certDir = getCmdOption(argv, argv + argc, "-C");
      //certDirExists = true;
      return CERT_DIR;
    }
  }
  return 1;
}

static void parse_file(const char *filename) {
  xmlParserCtxtPtr ctxt; /* the parser context */
  xmlDocPtr doc; /* the resulting document tree */

  /* create a parser context */
  ctxt = xmlNewParserCtxt();
  if (ctxt == NULL)
  {
    fprintf(stderr, "Error: Failed to allocate parser context\n");
    return;
  }
  /* parse the file, activating the DTD validation option */
  doc = xmlCtxtReadFile(ctxt, filename, NULL, XML_PARSE_DTDVALID);
  /* check if parsing suceeded */
  if (doc == NULL)
  {
      fprintf(stderr, "Error: Failed to parse %s\n", filename);
  }
  else
  {
  /* check if validation suceeded */
    if (ctxt->valid == 0) fprintf(stderr, "Error: Failed to validate %s\n", filename);


  /* free up the resulting document */
    xmlFreeDoc(doc);
  }
  /* free up the parser context */
  xmlFreeParserCtxt(ctxt);
}


int main(int argc, char *argv[]) {

  if(cmdOptionExists(argv, argv+argc, "-h") || cmdOptionExists(argv, argv+argc, "--help"))
  {
      printf("HELP message\n");
  }
  else if(cmdOptionExists(argv, argv+argc, "-f"))
  {
    char * filename = getCmdOption(argv, argv + argc, "-f");

    if (filename)
    {
      printf("Got a feedfile %d\n",argc );
      feedFile = filename;  //Feed file stored
    }

  }
  if(argc < 3)
  {
    char * getURL = argv[1];

    if (getURL)
    {
      printf("%s\n", getURL);
      //todo open file for read
    }
    else
    {
      printf("Empty\n");
    }
  }
  /*  Checks if we have got right argumets */
  if(argExists(argv) == 0)
  {
    printf("CORRECT\n" );

    /* Initializing OpenSSL */

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /*  Start setting SSL connection  */
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL ssl;

    if(certExists(argv, argc) == CERT_FILE)
    {
      printf("YEs got -c with file: %s\n", certFile);
      if(! SSL_CTX_load_verify_locations(ctx, certFile, NULL))
      {
        //TODO handle failed load
      }
    }
    else if(certExists(argv, argc) == CERT_DIR)
    {
      printf("YES got -C\n");
      /*   prepares a folder for use as the path parameter to SSL_CTX_load_verify_locations.  */
      c_rehash certDir;

      if(! SSL_CTX_load_verify_locations(ctx, NULL, certDir))
      {
        //TODO handle error
      }


    }
    else
    {
      printf("NO -c || -C\n" );
      /*  Loading default cert file */
      if(! SSL_CTX_set_default_verify_paths(ctx))
      {
        //TODO handle error
      }

    }
  }
  else
  {
    printf("ER\n" );
  }


  //file specfied
  LIBXML_TEST_VERSION

  parse_file(feedFile);
  xmlCleanupParser();


  return 0;
}
