all: ids 

ids: ids.cpp
	g++ ids.cpp -o ids -lpcap
