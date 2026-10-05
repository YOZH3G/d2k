#ifndef D2K_PANEL_UPDATE_H
#define D2K_PANEL_UPDATE_H
#include "server.h"
int d2k_panel_update_handle(int fd, const d2k_panel_config *, const char *,
                            const char *);
/* Shared with existing panel controls, preserving the current origin policy. */
int d2k_panel_same_origin(const char *);
#endif
