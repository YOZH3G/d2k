#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "../src/daemon.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
int main(void) {
  char root[] = "/tmp/d2ku-platform-XXXXXX";
  assert(mkdtemp(root));
  d2ku_ctx c = {0};
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  d2ku_daemon d = {.ctx = &c};
  assert(d2ku_daemon_config(&d, NULL) == D2KU_ABSENT);
  char file[256];
  snprintf(file, sizeof file, "%s/public.conf", root);
  int fd = open(file, O_CREAT | O_WRONLY, 0600);
  assert(fd >= 0);
  const char *b = "D2KU-CONFIG-1\nfeed=https://localhost:4443/"
                  "releases\nhost=localhost\nca=/test/"
                  "ca.pem\nabi=arm64\nbuild=1791000000\nkey="
                  "010000000000000000000000000000000000000000000000000000000000"
                  "0000 1 4102444800\n";
  assert(write(fd, b, strlen(b)) == (ssize_t)strlen(b));
  close(fd);
  assert(d2ku_daemon_config(&d, file) == D2KU_OK);
  assert(c.trust_count == 1 &&
         !strcmp(d.feed, "https://localhost:4443/releases"));
  chmod(file, 0666);
  assert(d2ku_daemon_config(&d, file) != D2KU_OK);
  chmod(file, 0600);
  assert(d2ku_platform_clock(&c.clock) == D2KU_OK);
  d2ku_clock_sample s;
  assert(c.clock.snapshot(c.clock.arg, &s) == D2KU_OK);
  assert(s.boot_id[0] && s.timezone[0] && s.local_date > 20200000);
  c.clock.last_accepted_timestamp = INT64_MAX;
  int64_t utc;
  assert(c.clock.wall(c.clock.arg, &utc) == D2KU_TIME);
  fd = open(file, O_WRONLY | O_TRUNC);
  assert(fd >= 0);
  assert(write(fd, "MSK-3\n", 6) == 6);
  close(fd);
  assert(d2ku_platform_timezone(file) == D2KU_OK);
  assert(c.clock.snapshot(c.clock.arg, &s) == D2KU_OK);
  assert(!strcmp(s.timezone, "MSK-3"));
  struct tm utc_tm;
  time_t epoch = (time_t)s.utc_seconds;
  assert(gmtime_r(&epoch, &utc_tm));
  assert(s.local_minute ==
         (unsigned)((utc_tm.tm_hour * 60 + utc_tm.tm_min + 180) % 1440));
  fd = open(file, O_WRONLY | O_TRUNC);
  assert(fd >= 0);
  assert(write(fd, "UTC0\n", 5) == 5);
  close(fd);
  assert(d2ku_platform_timezone(file) == D2KU_OK);
  assert(c.clock.snapshot(c.clock.arg, &s) == D2KU_OK &&
         !strcmp(s.timezone, "UTC0"));
  unlink(file);
  close(c.root_dirfd);
  rmdir(root);
  puts("platform: strict bootstrap trust config, real clock, floor: PASS");
}
