// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <string.h>
#include <inih/inih.h>
#include <teavpn2/common.h>

const char *data_dir = NULL;

struct user_parse_ctx {
	const char	*user;
	const char	*pass;
	const char	*userfile;
	char		fuser[0x100];
	char		fpass[0x100];
	struct if_info	iff;
};


static int userfile_parse_auth(struct user_parse_ctx *ctx, const char *name,
			       const char *val, int lineno)
{
	char *mutable_val;
	memcpy(&mutable_val, &val, sizeof(mutable_val));

	if (!strcmp(name, "username")) {
		strncpy(ctx->fuser, val, sizeof(ctx->fuser));
		ctx->fuser[sizeof(ctx->fuser) - 1] = '\0';
	} else if (!strcmp(name, "password")) {
		strncpy(ctx->fpass, val, sizeof(ctx->fpass));
		ctx->fpass[sizeof(ctx->fpass) - 1] = '\0';
	} else {
		pr_warn("Invalid name \"%s\" in section auth in %s:%d", name,
			ctx->userfile, lineno);
	}

	memset(mutable_val, 0, strlen(mutable_val));
	return 1;
}


static int userfile_parse_iface(struct user_parse_ctx *ctx, const char *name,
				const char *val, int lineno)
{
	if (!strcmp(name, "mtu")) {
		ctx->iff.ipv4_mtu = (uint16_t)strtoul(val, NULL, 10);
	} else if (!strcmp(name, "ipv4")) {
		strncpy(ctx->iff.ipv4, val, sizeof(ctx->iff.ipv4));
		ctx->iff.ipv4[sizeof(ctx->iff.ipv4) - 1] = '\0';
	} else if (!strcmp(name, "ipv4_netmask")) {
		strncpy(ctx->iff.ipv4_netmask, val, sizeof(ctx->iff.ipv4_netmask));
		ctx->iff.ipv4_netmask[sizeof(ctx->iff.ipv4_netmask) - 1] = '\0';
	} else if (!strcmp(name, "ipv4_dgateway")) {
		strncpy(ctx->iff.ipv4_dgateway, val, sizeof(ctx->iff.ipv4_dgateway));
		ctx->iff.ipv4_dgateway[sizeof(ctx->iff.ipv4_dgateway) - 1] = '\0';
	} else {
		pr_warn("Invalid name \"%s\" in section iface in %s:%d", name,
			ctx->userfile, lineno);
	}
	return 1;	
}


/*
 * If success, returns 1.
 * If failure, returns 0.
 */
static int userfile_parser(void *user, const char *section, const char *name,
			   const char *val, int lineno)
{
	struct user_parse_ctx *ctx = user;

	if (!strcmp(section, "auth")) {
		userfile_parse_auth(ctx, name, val, lineno);
	} else if (!strcmp(section, "iface")) {
		userfile_parse_iface(ctx, name, val, lineno);
	} else {
		pr_warn("Invalid section \"%s\" in %s:%d", section,
			ctx->userfile, lineno);
	}
	return 1;
}


static int _teavpn2_auth(FILE *handle, const char *userfile,
			 const char *username, const char *password, 
			 struct if_info *iff)
{
	int ret = 0;
	struct user_parse_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.user = username;
	ctx.pass = password;
	ctx.userfile = userfile;
	ret = ini_parse_file(handle, userfile_parser, &ctx);
	if (ret) {
		prl_notice(2, "Failed to parse config file \"%s\"", userfile);
		ret = -EINVAL;
		goto out;
	}

	if (strcmp(ctx.user, ctx.fuser)) {
		pr_warn("username in file \"%s\" does not match with the file "
			"name", ctx.userfile);
	}

	if (strcmp(ctx.pass, ctx.fpass)) {
		ret = -EACCES;
		goto out;
	}

	*iff = ctx.iff;
out:
	memset(&ctx, 0, sizeof(ctx));
	__asm__ volatile("":"+m"(ctx)::"memory");
	return ret;
}


bool teavpn2_auth(const char *username, const char *password,
		  struct if_info *iff)
{
	int err = 0;
	FILE *handle;
	bool ret = true;
	char userfile[512];

	if (unlikely(!data_dir))
		panic("data_dir is NULL");

	snprintf(userfile, sizeof(userfile), "%s/users/%s.ini", data_dir,
		 username);

	handle = fopen(userfile, "rb");
	if (!handle) {
		err = errno;
		prl_notice(2, "Cannot open user file: \"%s\": " PRERF, userfile,
			   PREAR(err));
		errno = err;
		return false;
	}

	err = _teavpn2_auth(handle, userfile, username, password, iff);
	if (err) {
		errno = -err;
		ret = false;
	}

	fclose(handle);
	return ret;
}
