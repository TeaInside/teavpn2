
#include <string.h>
#include <stdlib.h>

#include <inih/inih.h>
#include <teavpn2/client/common.h>
#include <teavpn2/global/helpers/arena.h>

struct parse_struct {
	bool  		exec;
	struct cli_cfg	*cfg;
};

extern char d_cfg_file_client[];

static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{

}

int teavpn_client_cfg_parse(struct cli_cfg *cfg)
{
	struct parse_struct cx;
	char *cfg_file = cfg->cfg_file;

	cx.exec = true;
	cx.cfg = cfg;

	if (cfg_file == NULL)
		return 0;

	if (ini_parse(cfg_file, parser_handler, &cx) < 0)
		return strcmp(cfg_file, d_cfg_file_client) ? -ENOENT : 0;

	if (!cx.exec) {
		pr_error("Error loading config file!");
		return -EINVAL;
	}

	return 0;
}
