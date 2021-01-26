# Make File for SFTCrypt - just run 'make'

all: sftcrypt.cpp
	c++ -o sftcrypt sftcrypt.cpp

clean:
	-rm sftcrypt

