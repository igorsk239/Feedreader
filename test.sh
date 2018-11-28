#!/bin/bash

#
 # File:   test.sh
 # Author:   Igor Ignác
 # Project:  Čtečka novinek ve formátu Atom s podporou TLS
 # Description:  Skript pre spustenie testov pre feedreader
 # Date: 16.11.2018
 # Faculty: Faculty of Information Technology, Brno University of Technology
#

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

export MALLOC_CHECK_=0

retval=0

make

timeout 6 ./feedreader http://www.fit.vutbr.cz/news/news-rss.php > /dev/null 2>&1

retval=$(echo $?)
if [[ "$retval" -eq "0" ]]; then
  echo "${green}[TEST PASSED]${reset}"
else
  echo "${red}[TEST FAILED]${reset}"
fi

timeout 6 ./feedreader http://www.fit.vutbr.cz/news/news-rss.php -u > /dev/null 2>&1

retval=$(echo $?)
if [[ "$retval" -eq "0" ]]; then
  echo "${green}[TEST PASSED]${reset}"
else
  echo "${red}[TEST FAILED]${reset}"
fi

timeout 6 ./feedreader http://www.fit.vutbr.cz/news/news-rss.php -a > /dev/null 2>&1

retval=$(echo $?)
if [[ "$retval" -eq "0" ]]; then
  echo "${green}[TEST PASSED]${reset}"
else
  echo "${red}[TEST FAILED]${reset}"
fi

timeout 6 ./feedreader http://www.fit.vutbr.cz/news/news-rss.php -a -u -T > /dev/null 2>&1

retval=$(echo $?)
if [[ "$retval" -eq "0" ]]; then
  echo "${green}[TEST PASSED]${reset}"
else
  echo "${red}[TEST FAILED]${reset}"
fi

timeout 6 ./feedreader

retval=$(echo $?)
if [[ "$retval" -eq "200" ]]; then
  echo "${green}[TEST PASSED]${reset}"
else
  echo "${red}[TEST FAILED]${reset}"
fi

timeout 15 ./feedreader -f feedfile -a -u -T > /dev/null 2>&1

retval=$(echo $?)
if [[ "$retval" -eq "0" ]]; then
  echo "${green}[TEST PASSED]${reset}"
else
  echo "${red}[TEST FAILED]${reset}"
fi

timeout 6 ./feedreader http://www.fit.vutbr.cz/news/news-rss.php -c /dev/null 2>&1 > /dev/null 2>&1

retval=$(echo $?)
if [[ "$retval" -eq "201" ]]; then
  echo "${green}[TEST PASSED]${reset}"
else
  echo "${red}[TEST FAILED]${reset}"
fi
