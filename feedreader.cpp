/**
 * File: feeder.cpp
 * Author: Igor Ignác xignac00@fit.vutbr.cz
 * Name: ISA project
 * Created: 2018/2019
 * Faculty: Faculty of Information Technology, Brno University of Technology
*/

#include "feedreader.h"

static const char * params[5] = {"-c", "-C", "-T", "-a", "-u"};
static const char * certFile;
static const char * certDir;

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

/**
 * Printing help message
 */
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

/**
 * Searches used arguments for feedreader
 * @param argv[]  command line arguments
 * @param pos position of parsed argument
 */
static void search_param(char* argv[], int pos)
{
  if(strcmp(argv[pos], "-u") == 0) url_arg = true;
  else if (strcmp(argv[pos], "-T") == 0) update_arg = true;
  else if (strcmp(argv[pos], "-a") == 0) author_arg = true;
}

/**
 * Searches used arguments for feedreader and sets error codes
 * @param argv[]  command line arguments
 * @param argc position of parsed argument
 * @return ERROR_PARAMS on error
 */
static int argExists(char *argv[], int argc)
{
  if(argv[2] != NULL)
  {
    for( unsigned int a = 0; a < sizeof(params)/sizeof(params[0]); a = a + 1 )
    {
      if(strcmp(params[a],argv[2]) == 0){paramError = false; break;}
      else  {
         paramError = true;
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
  if(paramError)
  {
     return ERROR_PARAMS;
  }

  return CORRECT;
}

/***************************************************************************************
*    Title: Parsing C++ arguments
*    Author: 0x90
*    Date: Mar 16, 2018 13:17
*    Code version: 4.0
*    Availability: https://stackoverflow.com/questions/865668/how-to-parse-command-line-arguments-in-c
*
***************************************************************************************/
char* getCmdOption(char ** begin, char ** end, const string & option)
{
    char ** itr = find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const string& option)
{
    return find(begin, end, option) != end;
}
/***************************************************************************************
*   end of citation
****************************************************************************************/


int certExists(char *argv[], int argc)
{
  for(int a = 0; a < argc; a = a + 1 )
  {
    if(strcmp(argv[a], "-c") == 0)
    {
      certFile = getCmdOption(argv, argv + argc, "-c");
      return CERT_FILE;
    }
    else if (strcmp(argv[a], "-C") == 0)
    {
      certDir = getCmdOption(argv, argv + argc, "-C");
      return CERT_DIR;
    }
  }
  return 1;
}

/**
 * Parses given atom feed in xml format
 *
 * Function parses xml from xmlTree which is store in program memory. Parsing is handled in switch
 * where function interates over the tree node by node and searches for XML_ELEMENT_NODE and XML_READER_TYPE_TEXT
 * nodes. After success fucntion prints this elements: title, updated, id, name
 */
static void atom_parse()
{

  int ret;
  string xml_type = "";

  bool title_val = false; //page title
  bool header_title = false;
  bool entry_val = false; //entry detection
  bool entry_title_val = false;
  bool update_val = false;
  bool url_val = false;
  bool author_val = false;

  ret = xmlTextReaderRead(reader);

  while (ret == 1) {

      const xmlChar *val;
      ret = xmlTextReaderRead(reader);

      switch (xmlTextReaderNodeType(reader))  { /* Reading the xml tree and processing nodes  */
        case XML_ELEMENT_NODE:  /* main elements of xml */
              if(xmlStrEqual(xmlTextReaderConstLocalName(reader), BAD_CAST "title"))
              {
                header_title = false;
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

        case XML_READER_TYPE_TEXT:  /* text values of elements */
              if(title_val){
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("*** %s ***\n", val);  //main title
                  header_title = true;
                  title_val = false;
                  break;
                }
              }
              else if (entry_title_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  if(entry_val == false) break;
                  else
                  {
                    printf("\n%s\n", val);  //entry title val
                    entry_title_val = false;
                    entry_val = false;
                    break;
                  }
                }
              }
              else if(url_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  //if(entry_val){
                    if(!header_title)
                    {
                      printf("URL: %s\n", val);  //url val
                      url_val = false;
                      header_title = false;
                      break;
                    }
                  //}
                }
              }
              else if(update_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Aktualizace: %s\n", val);  //update val
                  update_val = false;
                  break;
                }
              }
              else if(author_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Autor: %s\n", val);  //author val
                  author_val = false;
                  break;
                }
              }
              break;
        default:

              break;
      }
  }
  xmlFreeTextReader(reader);  /*  free readerer */
  if (ret != 0) {
      fprintf(stderr, "ERROR: xmlTextReaderRead failed to parse given data\n");
      exit(ERROR_XML);
  }
}

/**
 * Parses given rss in xml format
 *
 * Function parses xml from xmlTree which is store in program memory. Parsing is handled in switch
 * where function interates over the tree node by node and searches for XML_ELEMENT_NODE and XML_READER_TYPE_TEXT
 * nodes. After success fucntion prints this elements: title, link, pubDate or dc:date, author or dc:creator
 */
static void parse_rss()
{
  bool main_title = true;
  bool ignore_title = false;
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
                    ignore_title = true;
                    main_title = false;
                    title = false;
                    break;
                  }
                  else
                  {
                    printf("\n%s\n", val);  //main title
                    title = false;
                    break;
                  }
                }
              }

              else if(link_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  if(ignore_title == false)
                  {
                    printf("URL: %s\n", val);  //url val
                    link_val = false;
                    break;
                  }
                  else ignore_title = false;
                }
              }

              else if(update_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Aktualizace: %s\n", val);  //update val
                  update_val = false;
                  break;
                }
              }
              else if(author_val)
              {
                val = xmlTextReaderConstValue(reader);
                if(val != NULL)
                {
                  printf("Autor: %s\n", val);  //author val
                  author_val = false;
                  break;
                }
              }
        default:

              break;
      }
    }
}
/**
 * Saving response from server to xml tree
 *
 * Function firstly strips http response from server and then stores the rest of the xml
 * to the program memory. Function also checks if the loaded xml type is rss or atom
 * @param data server response to http request and xml data
 */
static void save_to_tree(char * data)
{
  string strdata(data);
  string rss_check;
  string response_check = strdata.substr(0, 30);
  string valid_data = "HTTP/1.1 200 OK";

  if (response_check.find(valid_data) == std::string::npos) /* Search for valid HTTP response */
  {
    cerr << "ERROR: HTTP response detected an error - connection wasn't established : " << response_check.substr(0,12) << endl;
    exit(ERROR_SSL);
  }

  if(first_read)
  {
    strdata.erase(0,1);
    strdata.erase(0, strdata.find('<',0));

    rss_check = strdata.substr(strdata.find('<',0), strdata.find('<',0) + 60);
    if(rss_check.find("rss") != std::string::npos )
    {
      channel_type = RSS_CHANNEL;
    }
    strcpy(data, strdata.c_str());
    first_read = false;
  }

  reader = xmlReaderForMemory(data, strlen(data), NULL, NULL,
          XML_PARSE_DTDATTR |  /* default DTD attributes */
          XML_PARSE_NOENT);

  if(reader == NULL)
  {
    fprintf(stderr, "ERROR: failed to parse data\n");
    exit(ERROR_PARAMS);
  }
  if(channel_type == RSS_CHANNEL) parse_rss();  //parsing rss XML file
  else  atom_parse();  //parse atom XML
}

/**
 * Establish connection and load server data to buffer
 *
 * @param ssl ssl object
 * @param url_name name of the url from feedfile or command line
 * @param argv[] command line arguments
 * @param argc number of command line arguments
 */
static void establish_connection(SSL ssl, string url_name, char *argv[], int argc )
{
  SSL_CTX *ctx; /* Structure to hold the SSL information */
  ctx = SSL_CTX_new(SSLv23_client_method());  /* Creating the Structure */

  if(ctx == NULL)
  {
    fprintf(stderr, "ERROR: An error occured when creating SSL structure: Couldn't create an SSL structure\n" );
    exit(ERROR_SSL);
  }

  if(certExists(argv, argc) == CERT_FILE) /* check for -c */
  {
    if(! SSL_CTX_load_verify_locations(ctx, certFile, NULL))  /* Loading given certfile from command line */
    {
      fprintf(stderr, "ERROR: An error occured when trying to load certificates: Given certificate is not valid - %s\n", certFile);
      exit(ERROR_SSL);
    }
  }
  else if(certExists(argv, argc) == CERT_DIR) /* check for -C */
  {

    if(! SSL_CTX_load_verify_locations(ctx, NULL, certDir)) /* Loading certfile from given directory */
    {
      fprintf(stderr, "ERROR: An error occured when trying to load certificates from directory.\n"
                      "   No cert file is present in given directory - %s\n", certDir);
      exit(ERROR_SSL);
    }
  }
  else  /* Using default certificates */
  {
    if(! SSL_CTX_set_default_verify_paths(ctx)) /*  Loading default cert file */
    {
      fprintf(stderr, "ERROR: An error occured when trying to load certificates: Default certificates are not valid - probably out of date\n");
      exit(ERROR_SSL);
    }
  }
/***************************************************************************************
*    Title: Secure programming with the OpenSSL API
*    Author: Kenneth Ballard
*    Date: August 16, 2018
*    Code version: 1.0
*    Availability: https://developer.ibm.com/tutorials/l-openssl/
*
***************************************************************************************/
    /*  Creating new bio object */
    BIO * bio;
    bio = BIO_new_ssl_connect(ctx);
    /*  Retrieve pointer to the SSL structure */
    BIO_get_ssl(bio, &ssl);
    /*  If server wants new handshake  */
    SSL_set_mode(&ssl, SSL_MODE_AUTO_RETRY);
/***************************************************************************************
*   end of citation
****************************************************************************************/

  /*  Extract https or http from given URL  */
  string url = url_name;
  smatch match;
  regex expression ("^(http|https)://.*$");  /* request http or https url type */

  if(! regex_search(url, match, expression))
  {
   cerr << "ERROR: Given URL is not in right format - " << url_name << endl;
   exit (ERROR_PARAMS);
  }

  const string url_str = url_name;

  regex rgx(".*://([^/]+)");  /* Scan whole url to check if it is well formated */
  smatch match_inside_url;
  if (! std::regex_search(url_str.begin(), url_str.end(), match_inside_url, rgx))
  {
   cerr << "ERROR: Given URL is not in right format - " << url_name << endl;
   exit (ERROR_PARAMS);
  }

  std::string str_url = match_inside_url[1];
  std::string page_name = str_url;

  const char * port = ":443"; /* Port we are using */
  str_url += port;

  /*  HOST value for HTTP request */
  char *getURL = new char[str_url.length() + 1];
  strcpy(getURL, str_url.c_str());
  char * host_name = new char[page_name.length() + 1];
  strcpy(host_name, page_name.c_str());

  /*  GET value */
  string get_request = url_name;
  /* Checks if given url is in right format */
  try {
    get_request = get_request.substr(get_request.find("/") + 2);
    get_request = get_request.substr(get_request.find("/"));

  } catch(...)  {
    cerr << "ERROR: Given URL is not in right format - " << url_name << endl;
    exit(ERROR_PARAMS);
  }
  /*  Create a connection  */
  BIO_set_conn_hostname(bio, getURL);

  /*  Verify that connection is open and also perform the handshake */
  if(BIO_do_connect(bio) <= 0)
  {
   fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
   fprintf(stderr, "ERROR: BIO_do_connect connection wasn't opened successfully\n");
   exit(ERROR_SSL);
  }

  /*  Check if a certificate is valid */
  if(SSL_get_verify_result(&ssl) != X509_V_OK)
  {
   fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
   fprintf(stderr,"ERROR: SSL_get_verify_result : certificate didn't pass OpenSSL’s internal checks\n" );
   //exit(ERROR_SSL);
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
     char buf[MaxBytesPerRecv]; /*  buffer of 1024 size */

     x = BIO_read(bio, buf, MaxBytesPerRecv-1); // -1 for end character

     string string_buff(buf); //convert buf to string
     server_data += string_buff; //append

     memset(buf, 0, sizeof buf);  //clear buffer

     /* Whole page have been read -> connection closed  */
     if (x == 0) break;

     else if(x < 0)
     {
       if(! BIO_should_retry(bio))
       {
         fprintf(stderr, "ERROR: BIO_should_retry an error occured\n" );
         fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
         exit(ERROR_SSL);
       }
       fprintf(stderr, "ERROR: BIO_read\n");
     }
  }
  size_t storage = server_data.size();
  char * data = (char *)malloc(sizeof(string)*storage);

  strcpy(data, server_data.c_str());  //copy string to buff
  save_to_tree(data);

  server_data.clear();
  free(data);
  delete [] getURL;
  delete [] host_name;

  /*  End of comunication, freeing the memory */
  xmlCleanupParser();
  BIO_free_all(bio);
  SSL_CTX_free(ctx);
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
      exit(ERROR_PARAMS);
    }
  }
  else if(argc == 1)
  {
    fprintf(stderr, "ERROR: No file specified in -f or URL, run -h or --help !\n");
    exit(ERROR_PARAMS);
  }

  /* Initializing */
  argExists(argv,argc);
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  /*  Start setting SSL connection  */
  SSL ssl;
  string url_name;

  if(fileSpecified)
  {
    /* We have feedfile so HTTP requests depend on its content */
    while (getline(feedfile, url_name))
    {
      if(url_name.length() == 0 || url_name[0] == '#'){;} //skip empty line and commentary
      else
      {
        establish_connection(ssl, url_name, argv, argc);
        first_read = true;
      }
    }
    if(fileSpecified) feedfile.close(); //closing file after read
  }
  /* connect for specified URL */
  else
  {
    string str_argv(argv[1]);
    establish_connection(ssl, str_argv, argv, argc);
  }
  return CORRECT;
}
