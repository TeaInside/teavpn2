// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/auth.c
 *
 *  Authentication helper for TeaVPN2 server.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inih/inih.h>
#include <bluetea/lib/string.h>
#include <teavpn2/server/auth.h>


struct auth_parse_ctx {
	const char	*file;
	char		user[0x100];
	char		pass[0x100];
	char		ipv4[IPV4_L];
	char		ipv4_nm[IPV4_L];
	char		ipv4_dgw[IPV4_L];
	uint16_t	mtu;
};


union be_mutable {
	const void	*const_ptr;
	void		*ptr;
};


static void parse_section_auth(struct auth_parse_ctx *ctx, const char *name,
			       const char *value)
{
	union be_mutable bx;
	bx.ptr = NULL;

	if (!strcmp(name, "username")) {
		sane_strncpy(ctx->user, value, sizeof(ctx->user));
		bx.const_ptr = value;
	} else if (!strcmp(name, "password")) {
		sane_strncpy(ctx->pass, value, sizeof(ctx->pass));
		bx.const_ptr = value;
	}

	if (bx.ptr)
		memset(bx.ptr, 0, strlen((char *)bx.ptr));
}


static void parse_section_iface(struct auth_parse_ctx *ctx, const char *name,
				const char *value)
{
	if (!strcmp(name, "ipv4")) {
		sane_strncpy(ctx->ipv4, value, sizeof(ctx->ipv4));
	} else if (!strcmp(name, "ipv4_netmask")) {
		sane_strncpy(ctx->ipv4_nm, value, sizeof(ctx->ipv4_nm));
	} else if (!strcmp(name, "ipv4_dgateway")) {
		sane_strncpy(ctx->ipv4_dgw, value, sizeof(ctx->ipv4_dgw));
	} else if (!strcmp(name, "mtu")) {
		ctx->mtu = (uint16_t)strtoul(value, NULL, 10);
	}
}


static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	struct auth_parse_ctx *ctx = user;

	if (!strcmp(section, "auth")) {
		parse_section_auth(ctx, name, value);
	} else if (!strcmp(section, "iface")) {
		parse_section_iface(ctx, name, value);
	}
	(void)lineno;
	return 0;
}


static bool do_auth(const char *data_dir, const char *user, const char *pass,
		    struct tsrv_pkt_auth_res *auth_res)
{
	FILE *handle;
	bool ret = false;
	struct if_info *iff;
	char user_file[512];
	struct auth_parse_ctx ctx;

	snprintf(user_file, sizeof(user_file), "%s/users/%s.ini", data_dir, user);
	handle = fopen(user_file, "rb");
	if (unlikely(!handle)) {
		int err = errno;
		pr_notice("Cannot open user file: %s: " PRERF, user_file,
			  PREAR(err));
		return false;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.file = user_file;
	if (ini_parse_file(handle, parser_handler, &ctx) < 0)
		goto out;

	if (unlikely(!*ctx.user)) {
		pr_notice("Cannot find username entry in %s", user_file);
		goto out;
	}

	if (unlikely(!*ctx.pass)) {
		pr_notice("Cannot find password entry in %s", user_file);
		goto out;
	}

	if (unlikely(!*ctx.ipv4)) {
		pr_notice("Cannot find ipv4 entry in %s", user_file);
		goto out;
	}

	if (unlikely(!*ctx.ipv4_nm)) {
		pr_notice("Cannot find ipv4_netmask entry in %s", user_file);
		goto out;
	}

	if (unlikely(!ctx.mtu)) {
		pr_notice("Cannot find mtu entry (or it's zero) in %s",
			  user_file);
		goto out;
	}

	if (strcmp(pass, ctx.pass)) {
		pr_notice("Wrong password for user %s", user);
		goto out;
	}

	ret = true;
	auth_res->is_ok = 1;
	iff = &auth_res->iff;
	memset(iff, 0, sizeof(*iff));
	sane_strncpy(iff->ipv4, ctx.ipv4, sizeof(iff->ipv4));
	sane_strncpy(iff->ipv4_netmask, ctx.ipv4_nm, sizeof(iff->ipv4_netmask));
	if (*ctx.ipv4_dgw) {
		sane_strncpy(iff->ipv4_dgateway, ctx.ipv4_dgw,
			     sizeof(iff->ipv4_dgateway));
	}
	iff->mtu = ctx.mtu;
out:
	fclose(handle);

	if (!*ctx.user)
		memset(ctx.user, 0, sizeof(ctx.user));
	if (!*ctx.pass)
		memset(ctx.pass, 0, sizeof(ctx.pass));

	/*
	 * This memory clobber is to prevent compiler
	 * from removing the memset.
	 *
	 * The compiler knows that the lifetime of
	 * @ctx will end right after the memset. So
	 * it thinks the memset is not necessary and
	 * it optimizes the memset(s) out.
	 *
	 * The compiler is not allowed to assume so
	 * if we put a memory clobber here!
	 */
	__asm__ volatile("":"+m"(ctx)::"memory");
	return ret;
}


bool teavpn2_server_auth(const struct srv_cfg *cfg,
			 struct tcli_pkt_auth *auth,
			 struct tsrv_pkt_auth_res *auth_res)
{
	size_t ulen, plen;
	const char *data_dir;

	/*
	 * For safety in case the client sends non
	 * null terminated username/password.
	 */
	auth->username[sizeof(auth->username) - 1] = '\0';
	auth->password[sizeof(auth->password) - 1] = '\0';

	ulen = strlen(auth->username);
	plen = strlen(auth->password);

	if (ulen != (size_t)auth->ulen || plen != (size_t)auth->plen) {
		pr_notice("Got invalid authentication data length");
		return false;
	}

	data_dir = cfg->sys.data_dir;
	if (!do_auth(data_dir, auth->username, auth->password, auth_res)) {
		pr_notice("Got invalid authentication user data");
		auth_res->is_ok = 0;
		return false;
	}

	auth_res->is_ok = 1;
	return true;
}
