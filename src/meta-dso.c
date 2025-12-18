#define _GNU_SOURCE

#include <stdio.h>
#include <link.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "librunt.h"
#include "relf.h"
#include "maps.h"
#include "liballocs.h"
#include "liballocs_private.h"

#ifdef _LIBGEN_H
#error "meta-dso.c needs GNU basename() so must not include libgen.h"
#endif

const char *meta_base __attribute__((visibility("hidden")));
unsigned meta_base_len __attribute__((visibility("hidden")));

__attribute__((visibility("hidden")))
const char *ensure_meta_base(void)
{
	if (meta_base) return meta_base;
	// the user can specify where we get our -meta.so
	meta_base = getenv("META_BASE");
	if (!meta_base) meta_base = "/usr/lib/meta";
	meta_base_len = strlen(meta_base);
	return meta_base;
}

#define PATH_BUFFER_SIZE 4096

__attribute__((visibility("hidden")))
const char *meta_libfile_name_by_path(const char *objname, char *outbuf, size_t outbuf_len)
{
	/* we must have a canonical filename */
	if (objname[0] != '/') return NULL;
	ensure_meta_base();
	unsigned bytes_left = outbuf_len - 1;
	
	outbuf[0] = '\0';
	bytes_left--;
	// append the uniqtypes base path
	strncat(outbuf, meta_base, bytes_left);
	bytes_left -= (bytes_left < meta_base_len) ? bytes_left : meta_base_len;
	
	// now append the object name
	unsigned file_name_len = strlen(objname);
	assert(file_name_len > 0);
	strncat(outbuf, objname, bytes_left);
	bytes_left -= (bytes_left < file_name_len) ? bytes_left : file_name_len;
	
	// now append the suffix
	strncat(outbuf, META_OBJ_SUFFIX, bytes_left);
	// no need to compute the last bytes_left
	
	return outbuf;
}
__attribute__((visibility("hidden")))
const char *meta_libfile_name_by_build_id(char build_id[20], char *outbuf, size_t outbuf_len)
{
	ensure_meta_base();
	unsigned bytes_left = outbuf_len - 1;
	outbuf[0] = '\0';
	bytes_left--;

	// append the uniqtypes base path
	strncat(outbuf, meta_base, bytes_left);
	bytes_left -= (bytes_left < meta_base_len) ? bytes_left : meta_base_len;
	// append the infix we use for build-ID-based naming
#define BUILD_ID_INFIX "/.build-id/"
	strncat(outbuf, BUILD_ID_INFIX, bytes_left);
	bytes_left -= (bytes_left < sizeof BUILD_ID_INFIX - 1) ? bytes_left : sizeof BUILD_ID_INFIX - 1;

	/* Now append the build ID, as hex characters NOT the binary blob we have.
	 * Also note the slash: we separate out the first two chars of the hex string. */
	snprintf(outbuf + strlen(outbuf),
		bytes_left,
		"%02hhx/%02hhx%02hhx%02hhx%02hhx" "%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx"  "%02hhx%02hhx%02hhx%02hhx%02hhx",
		build_id[0], build_id[1], build_id[2], build_id[3], build_id[4],
		build_id[5], build_id[6], build_id[7], build_id[8], build_id[9],
		build_id[10], build_id[11], build_id[12], build_id[13], build_id[14],
		build_id[15], build_id[16], build_id[17], build_id[18], build_id[19]
	);
	bytes_left -= 40;

	// now append the suffix
	strncat(outbuf, META_OBJ_SUFFIX, bytes_left);
	// no need to compute the last bytes_left

	return outbuf;
}

/* This is our single function for grabbing a meta-DSO. If we need the filename
 * we should use realpath on the /proc/self/fd symlink (HACK: Linux-specific).
 * This will avoid TOCTOU races on the filename. */
__attribute__((visibility("hidden")))
int find_and_open_meta_libfile(struct allocs_file_metadata *meta)
{
	const char *objname = meta->m.filename;
	/* We might not have a build ID. We represent this, somewhat hackily,
	 * as a build ID of all-zero. We don't include the build ID as a
	 * candidate if it is all zeroes... use memcmpy().
	 * The by-build-ID path should be tried first. (This is tested for
	 * in the hello-build-ID test case.) */
	char zero_build_id[20]; bzero(zero_build_id, sizeof zero_build_id);
	_Bool have_build_id = (0 != memcmp(zero_build_id, meta->m.build_id, sizeof zero_build_id));
	/* meta_libfile_name_* want to write into a buffer, and we need up to
	 * two of them */
	char by_build_id[PATH_BUFFER_SIZE] = "";
	if (have_build_id) meta_libfile_name_by_build_id(meta->m.build_id, by_build_id, sizeof by_build_id);
	char by_path[PATH_BUFFER_SIZE] = "";
	meta_libfile_name_by_path(objname, by_path, sizeof by_path);
	const char *candidates[] = {
		have_build_id ? by_build_id : by_path,
		have_build_id ? by_path : NULL
	};
	int fd_meta = -1;
	for (int i = 0; i < sizeof candidates / sizeof candidates[0] && !!candidates[i]; ++i)
	{
		const char *candidate = candidates[i];
		/* open it and fstat it */
		int fd_meta = open(candidate, O_RDONLY);
		if (fd_meta == -1)
		{
			debug_printf(1, "Could not open meta-DSO `%s' (%s)\n", candidate, strerror(errno));
			continue;
		}
		struct stat statbuf_meta;
		int ret = fstat(fd_meta, &statbuf_meta);
		if (ret != 0)
		{
			debug_printf(1, "Could not fstat meta-DSO `%s' (%s)\n", candidate, strerror(errno));
			close(fd_meta);
			fd_meta = -1; continue;
		}
		// also stat the actual base DSO...
		struct stat statbuf_base;
		ret = stat(objname, &statbuf_base);
		if (ret != 0)
		{
			/* Is it a problem if we can't stat it? We just can't do our newer-than check. 
			 * FIXME: our approach here is already vulnerable to false positives e.g.
			 * if a new binary/metadata is being installed while an old process is running
			 * this code... we will compare against the timestamp of the new base binary. */
			debug_printf(0, "Could not stat base DSO `%s' (%s) -- deleted on disk?\n", objname, strerror(errno));
		}
		// is the base file newer than the meta file? if so, we don't load it
		if (statbuf_base.st_mtime > statbuf_meta.st_mtime)
		{
			debug_printf(0, "Declining to load out-of-date meta-DSO `%s'\n", candidate);
			close(fd_meta);
			fd_meta = -1; continue;
		}
		debug_printf(4, "Successfully opened meta-DSO `%s'\n", candidate);
		return fd_meta;
	}
	return -1;
}

