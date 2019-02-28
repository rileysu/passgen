#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <termios.h>
#include <unistd.h>

#define MAXPASS (256)
#define MAXIN (256)
#define SECMEMSIZE (16384)
#define HASHSIZE (32)

int main(void){
	if (!gcry_check_version(GCRYPT_VERSION)){
		fprintf(stderr, "libgcrypt version mismatch!\n");
		return 2;
	}

	char enctable[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
		'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5', '6',
		'7', '8', '9', '!', '@', '#', '$', '%', '^', '&', '*', '(',
		')', '-', '+', '{', '}', '[', ']', '\\', '/' };

	gcry_error_t err = 0;
	char *pass;
	char *in;
	gcry_md_hd_t hash;
	ssize_t readlen;
	struct termios old, new;

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

	if ((pass = gcry_malloc_secure(MAXPASS)) == NULL){
		fprintf(stderr, "Failure: Could not allocate memory\n");
		return 1;
	}
	if ((in = gcry_malloc_secure(MAXIN)) == NULL){
		fprintf(stderr, "Failure: Could not allocate memory\n");
		return 1;
	}

	if (err = gcry_md_open(&hash, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE)){
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not allocate memory\n");
		return 1;
	}

	printf("Type your password:\n");

	if (tcgetattr(fileno(stdin), &old) != 0){	
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not get terminal attributes\n");
		return 1;
	}

	new = old;
	new.c_lflag &= ~ECHO;

	if (tcsetattr (fileno(stdin), TCSAFLUSH, &new) != 0){
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not get terminal attributes\n");
		return 1;
	}

	//fgets(pass, MAXPASS, stdin);
	readlen = read(fileno(stdin), pass, MAXPASS-1);
	if (readlen < 0){	
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not read stdin\n");
		return 1;
	}
	pass[readlen] = '\0';

	tcsetattr(fileno(stdin), TCSAFLUSH, &old);

	printf("Type your destination or press ENTER to exit:\n");
	//fgets(in, MAXIN, stdin);
	readlen = read(fileno(stdin), in, MAXIN-1);
	if (readlen < 0){	
		gcry_free(pass);
		gcry_free(in);
		fprintf(stderr, "Failure: Could not read stdin\n");
		return 1;
	}
	in[readlen] = '\0';

	gcry_md_write(hash, pass, strlen(pass));
	gcry_md_write(hash, in, strlen(in));

	while(strcmp(in, "\n") != 0){
		printf("Unique password:\n");
		for (int i = 0; i < HASHSIZE; i++){
			unsigned char c = ((char*)gcry_md_read(hash, 0))[i] % sizeof(enctable);
			printf("%c", enctable[c]);
		}
		printf("\n\n");

		gcry_md_reset(hash);
		
		printf("Type your destination or press ENTER to exit:\n");
		//fgets(in, MAXIN, stdin);
		readlen = read(fileno(stdin), in, MAXIN-1);
		if (readlen < 0){	
			gcry_free(pass);
			gcry_free(in);
			fprintf(stderr, "Failure: Could not read stdin\n");
			return 1;
		}
		in[readlen] = '\0';

		gcry_md_write(hash, pass, strlen(pass));
		gcry_md_write(hash, in, strlen(in));
	}

	gcry_md_close(hash);
	gcry_free(pass);
	gcry_free(in);
	return 0;
}
