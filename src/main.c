#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <termios.h>
#include <unistd.h>

#define MAXPASS (256) //Max pass buffer
#define MAXIN (256) //Max location buffer
#define SECMEMSIZE (16384) //Secure memory allocation size
#define HASHSIZE (32) //Output password length

int main(void){
	//Check gcrypt version
	if (!gcry_check_version(GCRYPT_VERSION)){
		fprintf(stderr, "libgcrypt version mismatch!\n");
		return 2;
	}

	//Custom encoding table to convert hash into text for a password
	char enctable[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
		'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5', '6',
		'7', '8', '9', '!', '@', '#', '$', '%', '^', '&', '*', '(',
		')', '-', '+', '{', '}', '[', ']', '\\', '/' };

	gcry_error_t err; //Gcrypt error type
	char *pass; //Pass buffer pointer
	char *in; //Location buffer pointer
	gcry_md_hd_t hash; //Gcrypt hash type
	ssize_t readlen; //Readlen for stdin input
	struct termios old, new; //Termios struct to set echo off and then return to previous settings

	//Init securemem and check init finished, exit if there is an error
	if (err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN)){
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		return 1;
	}
	if (err = gcry_control(GCRYCTL_INIT_SECMEM, SECMEMSIZE)){
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		return 1;
	}
	if (err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN)){
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		return 1;
	}
	if (err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED)){
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		return 1;
	}

	//Alloc pass buffer to secure memory so it won't remain on ram after program exits
	if ((pass = gcry_malloc_secure(MAXPASS)) == NULL){
		fprintf(stderr, "Failure: Could not allocate memory\n");
		return 1;
	}

	//Similarly with the location buffer just in case there is somethin sensitive in there
	if ((in = gcry_malloc_secure(MAXIN)) == NULL){
		fprintf(stderr, "Failure: Could not allocate memory\n");
		return 1;
	}

	//Open SHA256 hash for use later
	if (err = gcry_md_open(&hash, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE)){
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not allocate memory\n");
		return 1;
	}
	
	//Prompt user to enter password
	printf("Type your password:\n");

	//If for some reason we can't blank the terminal input then exit
	if (tcgetattr(fileno(stdin), &old) != 0){	
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not get terminal attributes\n");
		return 1;
	}

	//Set new terminal such that it has no echo
	new = old;
	new.c_lflag &= ~ECHO;

	//Set terminal with new settings
	if (tcsetattr (fileno(stdin), TCSAFLUSH, &new) != 0){
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not get terminal attributes\n");
		return 1;
	}

	//Read password and handle case where there is an error with reading
	readlen = read(fileno(stdin), pass, MAXPASS-1);
	if (readlen < 0){	
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not read stdin\n");
		return 1;
	}

	//Add null to end of the buffer
	pass[readlen] = '\0';

	//Set terminal back to old settings
	tcsetattr(fileno(stdin), TCSAFLUSH, &old);

	//Prompt user to enter destination
	printf("Type your destination or press ENTER to exit:\n");
	
	//Read destination and handle case where there is an error with reading
	readlen = read(fileno(stdin), in, MAXIN-1);
	if (readlen < 0){	
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not read stdin\n");
		return 1;
	}

	//Add null to end of the buffer
	in[readlen] = '\0';

	//Append password and location to gcry to be hashed
	gcry_md_write(hash, pass, strlen(pass));
	gcry_md_write(hash, in, strlen(in));

	//User can exit by not entering anything (registers as a newline)
	while(strcmp(in, "\n") != 0){

		//Print the unique password
		printf("Unique password:\n");

		//Print each character by finding a corresponding char in the encoding table by using a corresponding 8 bit int
		//in the hash and finding its mod with respect to the size of the encoding table
		for (int i = 0; i < HASHSIZE; i++){
			unsigned char c = ((char*)gcry_md_read(hash, 0))[i] % sizeof(enctable);
			printf("%c", enctable[c]);
		}

		//Double newline to clean output
		printf("\n\n");

		//Reset hash for multiple outputs
		gcry_md_reset(hash);
		

		//Prompt user to enter destination
		printf("Type your destination or press ENTER to exit:\n");
	
		//Read destination and handle case where there is an error with reading
		readlen = read(fileno(stdin), in, MAXIN-1);
		if (readlen < 0){	
			gcry_free(pass);
			gcry_free(in);
			fprintf(stderr, "Failure: Could not read stdin\n");
			return 1;
		}

		//Add null to end of the buffer
		in[readlen] = '\0';

		//Append password and location to gcry to be hashed
		gcry_md_write(hash, pass, strlen(pass));
		gcry_md_write(hash, in, strlen(in));
	}

	//Free as much as we can before exiting the program
	gcry_md_close(hash);
	gcry_free(pass);
	gcry_free(in);

	//Exit
	return 0;

	//Unfortunately gycrypt doesn't free all memory although it seems that this isn't a memory leak since it's only
	//allocated once
}
