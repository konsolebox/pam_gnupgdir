/*
 * pam_gnupgdir — PAM module that creates /run/gnupg/user/$UID
 *                (or /var/run/gnupg/user/$UID) on session open.
 *
 * Copyright (c) 2026 konsolebox
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * -----------------------------------------------------------------------------
 *
 * This module was written with substantial assistance from Grok,
 * built by xAI[](https://grok.x.ai).
 */

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ALLOWED_BASE1 "/run/gnupg/user"
#define ALLOWED_BASE2 "/var/run/gnupg/user"

#define DEFAULT_BASE ALLOWED_BASE1
#define DEFAULT_MODE 0700

static int is_allowed_base(const char *base)
{
	return (strcmp(base, ALLOWED_BASE1) == 0 || strcmp(base, ALLOWED_BASE2) == 0);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	struct passwd *pw;
	char dir[PATH_MAX];
	const char *base = DEFAULT_BASE;
	mode_t mode = DEFAULT_MODE;
	int i, debug = 0;
	int skip_root = 0;

	(void)flags;

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
		pam_syslog(pamh, LOG_ERR, "Cannot get username");
		return PAM_SESSION_ERR;
	}

	pw = getpwnam(user);
	if (!pw) {
		pam_syslog(pamh, LOG_ERR, "User %s not found", user);
		return PAM_SESSION_ERR;
	}

	for (i = 0; i < argc; ++i) {
		if (strncmp(argv[i], "base=", 5) == 0) {
			base = argv[i] + 5;
			if (!is_allowed_base(base)) {
				pam_syslog(pamh, LOG_ERR, "Invalid base '%s' - only %s and %s allowed", base,
				           ALLOWED_BASE1, ALLOWED_BASE2);
				base = DEFAULT_BASE;
			}
		} else if (strncmp(argv[i], "mode=", 5) == 0) {
			mode = strtol(argv[i] + 5, NULL, 8);
		} else if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else if (strcmp(argv[i], "skip_root") == 0) {
			skip_root = 1;
		}
	}

	if (skip_root && pw->pw_uid == 0) {
		if (debug)
			pam_syslog(pamh, LOG_DEBUG, "Skipping root user as requested");
		return PAM_SUCCESS;
	}

	if (snprintf(dir, sizeof(dir), "%s/%u", base, (unsigned)pw->pw_uid) >= (int)sizeof(dir)) {
		pam_syslog(pamh, LOG_ERR, "Path too long for user %s", user);
		return PAM_SESSION_ERR;
	}

	mkdir(base, 0755);

	if (mkdir(dir, mode) == 0 || errno == EEXIST) {
		if (chown(dir, pw->pw_uid, pw->pw_gid) == 0) {
			if (debug)
				pam_syslog(pamh, LOG_DEBUG, "Ensured %s for user %s (%u)",
				           dir, user, (unsigned)pw->pw_uid);
		} else {
			pam_syslog(pamh, LOG_ERR, "chown failed on %s: %m", dir);
		}
	} else if (errno != EEXIST) {
		pam_syslog(pamh, LOG_ERR, "mkdir failed on %s: %m", dir);
	}

	return PAM_SUCCESS;
}

#define DEFINE_NOOP(name, ret) \
	PAM_EXTERN int pam_sm_##name(pam_handle_t *pamh, int flags, int argc, const char **argv) \
	{ (void)pamh; (void)flags; (void)argc; (void)argv; return ret; }

DEFINE_NOOP(close_session, PAM_SUCCESS)
DEFINE_NOOP(authenticate, PAM_IGNORE)
DEFINE_NOOP(setcred, PAM_IGNORE)
DEFINE_NOOP(acct_mgmt, PAM_IGNORE)
DEFINE_NOOP(chauthtok, PAM_IGNORE)
