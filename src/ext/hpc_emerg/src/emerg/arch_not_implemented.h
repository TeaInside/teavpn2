
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi <ammarfaizi2@gmail.com>
 */

#ifndef EMERG__SRC__ARCH_NOT_IMPLEMENTED_H
#define EMERG__SRC__ARCH_NOT_IMPLEMENTED_H

#define WARN()
#define WARN_ONCE()
#define WARN_ON(COND) ({ COND; })
#define WARN_ON_ONCE(COND) ({ COND; })
#define BUG()
#define BUG_ON(COND) ({ COND; })

#endif /* #ifndef EMERG__SRC__ARCH_NOT_IMPLEMENTED_H */
