#include "pam_shim.h"
#include <stdlib.h>

extern int go_pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, char **argv);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return go_pam_sm_authenticate(pamh, flags, argc, (char **)argv);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

const char *get_pam_user(pam_handle_t *pamh) {
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
        return NULL;
    }
    return user;
}

int do_conv(struct pam_conv *conv, int num_msg,
            const struct pam_message **msgs,
            struct pam_response **resp) {
    if (!conv || !conv->conv) return PAM_CONV_ERR;
    return conv->conv(num_msg, msgs, resp, conv->appdata_ptr);
}

int do_conv_single(struct pam_conv *conv, int msg_style,
                   const char *prompt, char **out_resp) {
    if (!conv || !conv->conv || !prompt || !out_resp) return PAM_CONV_ERR;
    *out_resp = NULL;

    struct pam_message msg;
    msg.msg_style = msg_style;
    msg.msg = prompt;

    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;

    int ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (ret != PAM_SUCCESS) return ret;

    if (resp) {
        if (resp[0].resp) {
            *out_resp = resp[0].resp;
        }
        free(resp);
    }
    return PAM_SUCCESS;
}
