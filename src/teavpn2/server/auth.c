
#include <inih/inih.h>
#include <teavpn2/auth.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/server/common.h>


struct user_info {
	struct iface_cfg	*iface;
	char			ufile[1023];
	bool			is_ok;
	char			look_uname[64];
	char			look_pass[64];
};

union const_castu {
	void *_no_const;
	const void *_const;
};


static int auth_parser_handler(void *user, const char *section,
			       const char *name, const char *value, int lineno)
{
	struct user_info *ctx   = (struct user_info *)user;
	struct iface_cfg *iface = ctx->iface;

	/* Section match */
	#define rmatch_s(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
	#define rmatch_n(STR) if (unlikely(!strcmp(name, (STR))))

	rmatch_s("auth") {
		rmatch_n("username") {
			strncpy(ctx->look_uname, value, 63);
			ctx->look_uname[63] = '\0';
		} else
		rmatch_n("password") {
			union const_castu ptr;
			ptr._const = value;

			strncpy(ctx->look_pass, value, 63);
			ctx->look_pass[63] = '\0';

			memzero_explicit(ptr._no_const, strnlen(value, 64));

		} else {
			goto out_invalid_name;
		}
	} else
	rmatch_s("iface") {
		rmatch_n("ipv4") {
			strncpy(iface->ipv4, value, IPV4_L - 1);
		} else
		rmatch_n("ipv4_netmask") {
			strncpy(iface->ipv4_netmask, value, IPV4_L - 1);
		} else
		rmatch_n("mtu") {
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
		 section, lineno, ctx->ufile);
out_err:
	ctx->is_ok = false;
	return false;
}


static bool validate_uname(const char *u)
{
	uint16_t i = 0;
	while (likely(*u)) {
		char c = *u++;
		bool is_allowed = (
				(('0' <= c) && (c <= '9'))
			||	(('A' <= c) && (c <= 'Z'))
			||	(('a' <= c) && (c <= 'z'))
			||	((c == '_') || (c == '-') || (c == '.'))
		);

		if (unlikely(++i >= 64))
			return false;
		if (unlikely(!is_allowed))
			return false;
	}
	return true;
}


bool teavpn_server_auth(struct srv_cfg *cfg, struct auth_ret *ret, char *uname,
			char *pass)
{
	bool retval;
	FILE *handle;
	struct user_info ctx;
	char *data_dir = cfg->data_dir;

	memset(&ctx, 0, sizeof(struct user_info));

	if (unlikely(!validate_uname(uname))) {
		uname[63] = '\0';
		prl_notice(0, "Invalid username: \"%s\"", uname);
		return false;
	}

	snprintf(ctx.ufile, sizeof(ctx.ufile), "%s/users/%s.ini", data_dir,
		 uname);

	handle = fopen(ctx.ufile, "r");
	if (unlikely(handle == NULL)) {
		int err = errno;
		prl_notice(0, "Cannot open user file (" PRERF "): %s",
			   PREAR(err), ctx.ufile);
		return false;
	}

	ctx.iface = &ret->iface;
	if (unlikely(ini_parse_file(handle, auth_parser_handler, &ctx) < 0)) {
		prl_notice(0, "Cannot parse file \"%s\"", ctx.ufile);
		retval = false;
		goto out_fclose;
	}


	if (unlikely(strncmp(ctx.look_pass, pass, 64) != 0)) {
		prl_notice(0, "Wrong password for username %s", uname);
		retval = false;
		goto out_fclose;
	}

	retval = true;
out_fclose:
	memzero_explicit(ctx.look_pass, sizeof(ctx.look_pass));
	fclose(handle);
	return retval;
}
