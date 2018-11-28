/**
 * File: feeder.h
 * Author: Igor Ignác xignac00@fit.vutbr.cz
 * Name: ISA project
 * Created: 2018/2019
 * Faculty: Faculty of Information Technology, Brno University of Technology
*/

#ifndef H_FEEDREADER
#define H_FEEDREADER

#include <stdio.h>
#include <regex>

#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <dirent.h>
#include <sys/types.h>

#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/xmlreader.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define CORRECT 0
#define ERROR_PARAMS 200
#define ERROR_SSL 201
#define ERROR_XML 202
#define CERT_FILE 20
#define CERT_DIR 21
#define RSS_CHANNEL 22
#define ATOM_CHANNEL 23

using namespace std;

/*  Function protypes */
static void usage();
static void search_param(char *argv[],int pos);
static int argExists(char *argv[], int argc);
char* getCmdOption(char ** begin, char ** end, const string & option);
bool cmdOptionExists(char** begin, char** end, const string& option);
int certExists(char *argv[], int argc);
static void atom_parse();
static void parse_rss();
static void save_to_tree(char * data);
static void establish_connection(SSL ssl, string url_name, char *argv[], int argc );

#endif
