#/*
# * File: ipk-client.cpp
# * Author: Igor Ignác xignac00@fit.vutbr.cz
# * Name: IPK project 1
# * Created: 2017/2018
# * Faculty: Faculty of Information Technology, Brno University of Technology
# * Usage: make all -> compile whole project
# *				 make clean -> clean all object files and binaries
# *				 make compress -> creates xignac00.tar
#*/
CPP = g++
CPPFLAGS = -static-libstdc++ -Wextra -pedantic -g -Wall -lxml2 -lm
LDLIBS = -lssl -lcrypto -lxml2 `xml2-config --cflags` `xml2-config --libs`
LDFLAGS = -L/usr/local/ssl/lib 
NAME1 = feedreader

all:
		$(CPP) -I/usr/include/libxml2/libxml -I/usr/include/glib-2.0 $(LDFLAGS) -o $(NAME1) $(NAME1).cpp $(CPPFLAGS) $(LDLIBS) 

compress:
		tar -cf xignac00.tar $(NAME1).cpp $(NAME1).h Makefile README manual.pdf feedfile test.sh
		gzip xignac00.tar

.PHONY: test

test:
	bash test.sh

prerequisites: test

target: prerequisites
	test.sh

clean:
		rm -f $(NAME1) $(NAME2) *.o
