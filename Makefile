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
LDLIBS = -lssl -lcrypto
LDFLAGS = -L/usr/local/ssl/lib 
NAME1 = feedreader
NAME3 = feedreader

all:
		$(CPP) -I/usr/include/libxml2 $(LDFLAGS) -o $(NAME1) $(NAME1).cpp $(CPPFLAGS) $(LDLIBS)

compress:
		tar -cf xignac00.tar $(NAME1).cpp $(NAME2).cpp $(NAME3).h Makefile Readme xignac00.pdf
		gzip xignac00.tar

clean:
		rm -f $(NAME1) $(NAME2) *.o
