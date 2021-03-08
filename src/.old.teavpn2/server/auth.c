
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inih/inih.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/server/auth.h>

struct parse_struct {
	bool  			is_ok;
	char			user_file[1024];
	char			tmp_user[256];
	char			tmp_pass[256];
	struct iface_cfg	*iface;
	struct auth_pkt		*auth;
};


int parser_handler_czzz(void *user, const char *section, const char *name,
			const char *value, int lineno)
{
	struct parse_struct *ctx = (struct parse_struct *)user;
	struct iface_cfg *iface = ctx->iface;

	/* Section match */
	#define RMATCH_S(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
	#define RMATCH_N(STR) if (unlikely(!strcmp(name, (STR))))

	RMATCH_S("auth") {
		RMATCH_N("username") {
			strncpy(ctx->tmp_user, value, 0xffu - 1u);
			ctx->tmp_user[0xffu - 1u] = '\0';
		} else
		RMATCH_N("password") {
			strncpy(ctx->tmp_pass, value, 0xffu - 1u);
			ctx->tmp_pass[0xffu - 1u] = '\0';
			memzero_explicit((void *)value, strnlen(value, 0xffu));
		} else {
			goto out_invalid_name;
		}
	} else
	RMATCH_S("iface") {
		RMATCH_N("ipv4") {
			strncpy(iface->ipv4, value, IPV4LEN);
		} else
		RMATCH_N("ipv4_netmask") {
			strncpy(iface->ipv4_netmask, value, IPV4LEN);
		} else
		RMATCH_N("mtu") {
			iface->mtu = (uint16_t)atoi(value);
		} else {
			goto out_invalid_name;
		}
	} else {
		pr_error("Invalid section \"%s\" on line %d", section, lineno);
		goto out_err;
	}

	return true;

	#undef RMATCH_N
	#undef RMATCH_S
out_invalid_name:
	pr_error("Invalid name \"%s\" in section \"%s\" on line %d in %s", name,
		 section, lineno, ctx->user_file);
out_err:
	ctx->is_ok = false;
	return false;
}


static bool validate_username(char *u)
{
	uint16_t i = 0;
	while (*u) {
		char c = *u++;
		bool cond =
		       (('A' <= c) && (c <= 'Z'))
		    || (('a' <= c) && (c <= 'z'))
		    || (('0' <= c) && (c <= '9'))
		    || ((c == '_') || (c == '-'));

		i++;
		if (!cond)
			return false;
	}

	return true && (i < 0xffu);
}


bool teavpn_server_get_auth(struct iface_cfg *iface, struct auth_pkt *auth,
			    struct srv_cfg *cfg)
{
	bool ret = true;
	FILE *handle = NULL;
	struct parse_struct ctx;
	char *username = auth->username;
	char *password = auth->password;

	ctx.is_ok = true;
	ctx.iface = iface;
	ctx.auth  = auth;

	if (!validate_username(username)) {
		prl_notice(0, "Invalid username %s", username);
		ret = false;
		goto out;
	}

	if (cfg->data_dir == NULL) {
		pr_error("cfg->data_dir is NULL");
		ret = false;
		goto out;
	}

	snprintf(ctx.user_file, sizeof(ctx.user_file) - 1, "%s/users/%s.ini",
		 cfg->data_dir, username);

	handle = fopen(ctx.user_file, "r");
	if (handle == NULL) {
		prl_notice(0, "Cannot open user file: \"%s\" (%s)",
			   ctx.user_file, strerror(errno));
		ret = false;
		goto out;
	}

	if (ini_parse_file(handle, parser_handler_czzz, &ctx) < 0) {
		prl_notice(0, "Cannot parse file \"%s\"", ctx.user_file);
		ret = false;
		goto out;
	}

	if (strncmp(ctx.tmp_pass, password, 0xffu) != 0) {
		prl_notice(0, "Wrong password for username %s", username);
		ret = false;
		goto out;
	}

out:
	if (handle)
		fclose(handle);

	memzero_explicit(ctx.tmp_pass, sizeof(ctx.tmp_pass));
	memzero_explicit(auth->password, sizeof(auth->password));
	return ret;
}
