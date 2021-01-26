
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <teavpn2/global/common.h>


char *shell_exec(const char *cmd, char *buf, size_t buflen, size_t *outlen)
{
	FILE *handle;
	bool use_malloc;
	size_t fread_len;

	use_malloc = (buf == NULL);

	if (use_malloc) {
		buf = malloc(buflen);
		if (buf == NULL) {
			pr_error("Cannot allocate memory: %s", strerror(errno));
			return NULL;
		}
	}


	handle = popen(cmd, "r");
	if (handle == NULL) {
		pr_error("Cannot execute popen(\"%s\"): %s", cmd,
			 strerror(errno));
		goto out_err;
	}

	fread_len = fread(buf, sizeof(char), buflen, handle);
	pclose(handle);

	if (outlen)
		*outlen = fread_len;

	return buf;
out_err:
	if (use_malloc)
		free(buf);

	return NULL;
}
