#ifndef PAM_SHIM_H
#define PAM_SHIM_H

#include <security/pam_appl.h>
#include <security/pam_modules.h>

const char *get_pam_user(pam_handle_t *pamh);
int do_conv(struct pam_conv *conv, int num_msg,
            const struct pam_message **msgs,
            struct pam_response **resp);
int do_conv_single(struct pam_conv *conv, int msg_style,
                   const char *prompt, char **out_resp);

#endif
