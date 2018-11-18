/*
 * File: feeder.cpp
 * Author: Igor Ignác xignac00@fit.vutbr.cz
 * Name: ISA project
 * Created: 2018/2019
 * Faculty: Faculty of Information Technology, Brno University of Technology
*/

#include "feedreader.h"

typedef std::vector<std::string> buffer_type;

static const char * params[5] = {"-c", "-C", "-T", "-a", "-u"};
static const char * certFile;
static const char * certDir;
//static bool certFileExists = false; certDirExists = false;
static bool paramError = false;
static bool fileSpecified = false;
static bool first_read = true;
static bool update_arg = false;
static bool author_arg = false;
static bool url_arg = false;

static int channel_type;

xmlTextReaderPtr reader;
ifstream feedfile;
static const size_t MaxBytesPerRecv = 1024;

static void usage() {
  printf("Usage: feedreader <URL | -f <feedfile>> [-c <certfile>] [-C <certaddr>] [-T] [-a] [-u]\n"
          "Feedreader of rss and atom with TLS support\n\n"
            "-f   to specify feedfile\n"
            "-c   to specify cert file\n"
            "-C   to specify cert directory\n"
            "-a   to extract author from feed/rss message\n"
            "-u   to extract url\n"
            "-T   to extract update time\n");
  exit(CORRECT);
}

static void search_param(char* argv[], int pos)
{
  if(strcmp(argv[pos], "-u") == 0) url_arg = true;
  else if (strcmp(argv[pos], "-T") == 0) update_arg = true;
  else if (strcmp(argv[pos], "-a") == 0) author_arg = true;
}

int argExists(char *argv[], int argc)
{
  if(argv[2] != NULL)
  {
    for( unsigned int a = 0; a < sizeof(params)/sizeof(params[0]); a = a + 1 )
    {
      if(strcmp(params[a],argv[2]) == 0){paramError = false; break;}
      else  {
         paramError = true;
         //if(strcmp(argv[a++],"-u") == 0) update_arg = true;
       }
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

  for (int i = 0; i < argc; i++) {
    search_param(argv, i);
  }
  if(paramError) return ERROR_PARAMS;
  //else if (argc > 6 != NULL) return ERROR_PARAMS;

  return CORRECT;
}

char *convert(const std::string & s)
{
   char *pc = new char[s.size()+1];
   std::strcpy(pc, s.c_str());
   return pc;
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

static void atom_parse()
{
  //xmlTextReaderPtr reader;  /* the parser context */

  int ret;
  string xml_type = "";
  bool title_val = false; //page title
  bool entry_val = false; //entry detection
  bool entry_title_val = false;
  bool update_val = false;
  bool url_val = false;
  bool author_val = false;

  bool rss_usage = true;

  ret = xmlTextReaderRead(reader);

  //const xmlChar *val;
  while (ret == 1) {
      //processNode(reader);
      ret = xmlTextReaderRead(reader);
      //processNode();

      const xmlChar *val;
      //printf("TYPE: %d  VALUE: %s\n",xmlTextReaderNodeType(reader),xmlTextReaderConstName(reader));
      switch (xmlTextReaderNodeType(reader))  {
        case XML_ELEMENT_NODE:
              //printf("NAME: %s\n",xmlTextReaderConstLocalName(reader) );
              if(xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "title"))
              {
                title_val = true;
                if(entry_val)
                {
                  entry_title_val = true;
                  title_val = false;
                }
              }
              else if(xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "entry")) entry_val = true;
              else if(update_arg && xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "updated")) update_val = true;
              else if(url_arg && xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "id")) url_val = true;
              else if(author_arg && xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "name")) author_val = true;

              break;

        case XML_READER_TYPE_TEXT:
              if(title_val){
                val = xmlTextReaderConstValue(reader);
                if(val == NULL)
                {
                  //no value read
                }
                else {
                  if(channel_type == RSS_CHANNEL)
                  {
                    if(rss_usage){ printf("*** %s ***\n", val); rss_usage = false;} //main title
                    else printf("%s\n", val);
                  }
                  else
                  {
                    printf("*** %s ***\n", val);  //main title
                    title_val = false;
                  }
                }
              }
              else if (entry_title_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("\n%s\n", val);  //entry val
                  entry_title_val = false;
                  entry_val = false;
                }
              }
              else if(url_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("URL: %s\n", val);  //url val
                  url_val = false;
                }
              }
              else if(update_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Aktualizace: %s\n", val);  //update val
                  update_val = false;
                }
              }
              else if(author_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Autor: %s\n", val);  //update val
                  author_val = false;
                }
              }
        default:
              //else
              break;
      }
  }
  xmlFreeTextReader(reader);
  if (ret != 0) {
      //fprintf(stderr, "ERROR: failed to parse given data\n");
  }
  //}

}

static void parse_rss()
{
  bool main_title = true;
  bool img_title = false;
  bool update_val = false;
  bool author_val = false;
  bool link_val = false;
  bool title = false;
  int ret = xmlTextReaderRead(reader);

  while (ret == 1) {

      const xmlChar *val;
      ret = xmlTextReaderRead(reader);

      switch (xmlTextReaderNodeType(reader))  {
        case XML_ELEMENT_NODE:

              if(xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "title")) title = true;
              else if(xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "img")) img_title = true;
              else if(url_arg && xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "link")) link_val = true;
              else if(update_arg && (xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "pubDate") || xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "dc:date"))) update_val = true;
              else if(author_arg && (xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "dc:creator") || xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "author" ))) author_val = true;

              break;

        case XML_READER_TYPE_TEXT:
              if(title)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  if(main_title)
                  {
                    printf("*** %s ***\n", val); //main title
                    main_title = false;
                    title = false;
                  }
                  else
                  {
                    if(img_title != true)
                    printf("\n%s\n", val);  //main title
                    title = false;
                  }
                }
              }

              else if(link_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("URL: %s\n", val);  //url val
                  link_val = false;
                }
              }

              else if(update_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Aktualizace: %s\n", val);  //update val
                  update_val = false;
                }
              }
              else if(author_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Autor: %s\n", val);  //author val
                  author_val = false;
                }
              }
        default:
              //else
              break;
      }
    }
}

static void save_to_tree(char * data)
{
  string strdata(data);
  string rss_check;
  //stripUnicode(strdata);
  if(first_read)
  {
    strdata.erase(0,1);
    strdata.erase(0, strdata.find('<',0));

    rss_check = strdata.substr(strdata.find('<',0), strdata.find('<',0) + 60);
    if(rss_check.find("rss") != std::string::npos )
    {
      channel_type = RSS_CHANNEL;
    }
    //std::cout << strdata;
    strcpy(data, strdata.c_str());
    first_read = false;
  }

  reader = xmlReaderForMemory(data, strlen(data), NULL, NULL,
          XML_PARSE_DTDATTR |  /* default DTD attributes */
          XML_PARSE_NOENT);

  if(reader == NULL)
  {
    fprintf(stderr, "ERROR: failed to parse data\n");
    //exit(ERROR_PARAMS);
  }
  if(channel_type == RSS_CHANNEL) parse_rss();  //parsing rss XML file
  else  atom_parse();  //parse atom XML


}

int main(int argc, char *argv[]) {

  if(cmdOptionExists(argv, argv+argc, "-h") || cmdOptionExists(argv, argv+argc, "--help"))
  {
      usage();
  }
  else if(cmdOptionExists(argv, argv+argc, "-f"))
  {
    char * filename = getCmdOption(argv, argv + argc, "-f");

    if (filename)
    {
      fileSpecified = true;

      feedfile.open(filename);
      if(feedfile.fail())
      {
        fprintf(stderr, "ERROR: Failed to open given file - %s\n", filename);
        exit(ERROR_PARAMS);
      }
    }
    else
    {
      fprintf(stderr, "ERROR: No file specified in -f, specify a feedfile!\n");
    }

  }

  /*  Checks if we have got right argumets */
  if(argExists(argv, argc) == 0)
  {
    printf("CORRECT\n" );
    /*if (fileSpecified == false) //!fileSpecified
    {*/
      /* Initializing OpenSSL */
      SSL_library_init();
      SSL_load_error_strings();
      ERR_load_BIO_strings();
      OpenSSL_add_all_algorithms();

      /*  Start setting SSL connection  */
      SSL_CTX *ctx;
      ctx = SSL_CTX_new(SSLv23_client_method());
      if(ctx == NULL)
      {
        printf("ERROR: CTX init failed\n" ); //TODO error
      }
      SSL ssl;

      if(certExists(argv, argc) == CERT_FILE)
      {
        printf("%s\n", certFile);
        if(! SSL_CTX_load_verify_locations(ctx, certFile, NULL))
        {
          //TODO handle failed load
          printf("ERRRRROR1\n" );
        }
      }
      else if(certExists(argv, argc) == CERT_DIR)
      {
        printf("YES got -C\n");
        /*   prepares a folder for use as the path parameter to SSL_CTX_load_verify_locations.  */
        //c_rehash certDir;

        if(! SSL_CTX_load_verify_locations(ctx, NULL, certDir))
        {
          //TODO handle error
          printf("ERRRRROR2\n" );
          exit(ERROR_PARAMS);
        }
      }
      else
      {
        printf("NO -c || -C\n" );
        /*  Loading default cert file */
        if(! SSL_CTX_set_default_verify_paths(ctx))
        {
          //TODO handle error
          printf("ERRRRROR3\n" );
        }
        /*  Creating new bio object */
        BIO * bio;
        bio = BIO_new_ssl_connect(ctx);
        /*  Retrieve pointer to the SSL structure */
        BIO_get_ssl(bio, &ssl);
        /*  If server wants new handshake  */
        SSL_set_mode(&ssl, SSL_MODE_AUTO_RETRY);

        /* We have feedfile so HTTP requests depend on its content */
        if(fileSpecified)
        {
          string url_name;
          while (getline(feedfile, url_name))
          {
            if(url_name.length() == 0 || url_name[0] == '#'){;}
            else
            {
              cout << url_name << endl;
            }
          }
        }
        //else
        //{
          //connect pre URL

        /*  Extract https or http from given URL  */
        string url = argv[1];
        std::smatch match;
        std::regex expression ("^(http|https)://.*$");

        if(! std::regex_search(url, match, expression))
        {
          fprintf(stderr, "ERROR: Given URL is not in right format %s\n", argv[1]);
          exit (ERROR_PARAMS);
        }

        const string url_str = argv[1];
        std::regex rgx(".*://([^/]+)");
        std::smatch match_inside_url;
        if (! std::regex_search(url_str.begin(), url_str.end(), match_inside_url, rgx))
        {
          fprintf(stderr, "ERROR: Given URL is not in right format %s\n", argv[1]);
          exit (ERROR_PARAMS);
        }

        std::string str_url = match_inside_url[1];
        std::string page_name = str_url;

        const char * port = ":443";
        str_url += port;

        /*  HOST value for HTTP request */
        char *getURL = new char[str_url.length() + 1];
        strcpy(getURL, str_url.c_str());
        char * host_name = new char[page_name.length() + 1];
        strcpy(host_name, page_name.c_str());

        /*  GET value */
        string get_request = argv[1];
        get_request = get_request.substr(get_request.find("/") + 2);
        get_request = get_request.substr(get_request.find("/"));

        /*  Create a connection  */
        BIO_set_conn_hostname(bio, getURL);

        /*  Verify that connection is open and also perform the handshake */
        if(BIO_do_connect(bio) <= 0)
        {
          //TODO handle failed connection
          printf("ERRRRROR4\n" );
          printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        }

        /*  Check if a certificate is valid */
        if(SSL_get_verify_result(&ssl) != X509_V_OK)
        {
          //TODO handle what went wrong
          printf("ERRRRROR5\n" );
          printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        }

        /*  HTTP request to server  */
        string request;
        request = string("GET ") + get_request + " HTTP/1.0\r\n";
        request +=string("Host: ") + host_name + "\r\n";
        request +=string("User-agent: Feedreader\r\n");
        request +=string("Accept: application/xml\r\n");
        request +=string("Accept-Charset: UTF-8,*\r\n");
        request +=string("Connection: Close\r\n\r\n");

        /*  Sending request */
        BIO_write(bio, request.c_str(), strlen(request.c_str()));


        /*  Reading Information from server */
        LIBXML_TEST_VERSION
        int x = 1;  //BIO_read return value
        string server_data;

        while (1)
        {
            /*const size_t oldSize = serverData.size();
            serverData.resize(oldSize + MaxBytesPerRecv);*/
            char buf[MaxBytesPerRecv];

            x = BIO_read(bio, buf, MaxBytesPerRecv-1);
            //atom_parse(buf);
            //string data(buf);
            string string_buff(buf);
            server_data += string_buff;

            memset(buf, 0, sizeof buf);
            if (x == 0) break;  //Read whole page

            else if(x < 0)
            {
              if(! BIO_should_retry(bio))
              {
                //TODO failed read here
                printf("ERRRRROR6\n" );
              }
              printf("ERROR7\n");
              //TODO do something to handle the retry
            }

            /*serverData.resize(oldSize + bytesRead);
            serverData.push_back(buf);*/
        }
        size_t storage = server_data.size();
        char * data = (char *)malloc(sizeof(string)*storage);

        strcpy(data, server_data.c_str());
        //cout << data << endl;
        save_to_tree(data);

        free(data);
        delete [] getURL;
        delete [] host_name;
        //}

        /*  End of comunication, freeing the memory */
        if(fileSpecified) feedfile.close();
        xmlCleanupParser();
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
      //}
    }
    //else //we have gotten feedfile from -f switch so we won't be opening SSL connecion
  }
  /*else
  {
    fprintf(stderr, "ERROR: INCORRECT USE OF PROGRAM feedreader use ./feedreader -h or --help to print help message\n");
    exit(ERROR_PARAMS);
  }*/

  return 0;
}
