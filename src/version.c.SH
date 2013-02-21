#! /bin/sh

#TODO: we should tag our version changes, and use git describe instead of git log.

echo "Extracting src/version.c ..."

git_command='git describe'

if [ -d ../.git ]; then
    if [ -x `which git` ]; then
        echo "Found git. version is"`$git_command`
        cvs_version="git:"`$git_command`
    else
        echo "No git installed. unknown git revision"
        cvs_version="git:unknown"
    fi
else
    echo "Not a git repository. leaving revision empty"
    cvs_version="release"
fi


/bin/cat >version.c <<!SUB!THIS!
/* version.c - CVS Version specific information.
 * Copyright 2000-2004 srvx Development Team
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srvx; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include "version.h"

const char *cvs_version = "$cvs_version";

!SUB!THIS!
