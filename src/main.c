/**
 * main.c 
 * 
 * Entrypoint file for sha256 algorithm program
 * 
 * Author Dalton Kinney
 * Created Jan 27, 2024
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sha256.h"

/**
 * usage
 * 
 * Prints the usage of the program
*/
void usage() { 
	char* usage_string = "Usage: sha256\n" 
						 "Given a file of data, return the sha256 hash over it\n\n" 
						 "-f      File of data to hash with sha256\n";
	printf("%s", usage_string);
}

int main(int argc, char* argv[]) { 
	int opt;        // Holds argument
	char* datafile; // Name of data file we will be hashing
	char* hash;     // Used to store the final hash

	// Parse arguments 
	if ((opt = getopt(argc, argv, "f:")) != -1 && opt == 'f') {
	    datafile = optarg;
		printf("File to be hashed: %s\n", datafile);
	} else { 
		usage();
		return 0;
	}

	// Ensure file exists and a file handle can be opened to it 
	FILE *pfile = fopen(datafile, "r");

	if (pfile == NULL) { 
		printf("%s does not exist! Exiting...\n", datafile);
		return 1;
	}

	// Perform sha256 and handle error if one occurs
	if ((hash = sha256(pfile)) == NULL) { 
		printf("Unable to perform sha256: %s\n", hash);
		return 1;
	}

	printf("%s %s\n", hash, datafile); // Print hash to stdout with file

	return 0;
}
