
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <inih/inih.h>
#include <teavpn2/server/argv.h>
#include <teavpn2/server/entry.h>
#include <teavpn2/server/config.h>
#include <teavpn2/global/helpers/arena.h>

struct parse_struct {
	bool  		exec;
	struct srv_cfg	*cfg;
};

extern char def_cfg_file[];

static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno);

int server_cfg_parse(struct srv_cfg *cfg)
{
	struct parse_struct cx;
	char *cfg_file = cfg->cfg_file;

	cx.exec = true;
	cx.cfg = cfg;

	if (cfg_file == NULL)
		return 0;

	if (ini_parse(cfg_file, parser_handler, &cx) < 0)
		return strcmp(cfg_file, def_cfg_file) ? -ENOENT : 0;



	return 0;
}


static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	struct parse_struct *cx = (struct parse_struct *)user;
	struct srv_cfg *cfg = cx->cfg;

	/* Section match */
	#define RMATCH_S(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
  	#define RMATCH_N(STR) if (unlikely(!strcmp(name, (STR))))


	RMATCH_S("iface") {
		RMATCH_N("dev") {
			cfg->iface.dev  = ar_strndup(value, 255);
		} else
		RMATCH_N("ipv4") {
			cfg->iface.ipv4 = ar_strndup(value, IPV4LEN);
		} else
		RMATCH_N("ipv4_netmask") {
			cfg->iface.ipv4_netmask = ar_strndup(value, IPV4LEN);
		} else
		RMATCH_N("mtu") {
			cfg->iface.mtu = (uint16_t)atoi(value);
		} else {
			goto out_inv_name;
		}
	} else
	RMATCH_S("socket") {

	} else
	RMATCH_S("other") {

	} else {
		pr_error("Invalid section \"%s\" on line %d\n", section,
			 lineno);
		goto out_err;
	}


	#undef RMATCH_N
	#undef RMATCH_S




	return true;

out_inv_name:
	pr_error("Invalid name \"%s\" in section \"%s\" on line %d",
		 name, section, lineno);

out_err:
	cx->exec = false;
	return false;
}
