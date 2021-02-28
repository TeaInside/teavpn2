
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <inih/inih.h>
#include <teavpn2/server/auth.h>


static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	/* Section match */
	#define RMATCH_S(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
	#define RMATCH_N(STR) if (unlikely(!strcmp(name, (STR))))


	return true;
}


bool teavpn_server_get_auth(struct iface_cfg *iface, struct auth_pkt *auth,
			    struct srv_cfg *cfg)
{
	FILE *handle;
	char user_file[1024];
	char *username = auth->username;

	if (cfg->data_dir == NULL) {
		pr_error("cfg->data_dir is NULL");
		return false;
	}

	snprintf(user_file, sizeof(user_file) - 1,"%s/users/%s.ini",
		 cfg->data_dir, username);

	handle = fopen(user_file, "r");
	if (handle == NULL) {
		prl_notice(0, "Cannot open user file: \"%s\" (%s)", user_file,
			   strerror(errno));
		return false;
	}

	if (ini_parse_file(handle, parser_handler, &ctx) < 0) {
		return false;
	}

	fclose(handle);
	return true;
}
