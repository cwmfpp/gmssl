
#include <stdio.h>
#include <stdlib.h>
#include <gmssl/sm2.h>

typedef struct _HjkInfo {
	SM2_KEY m_sm2_key_private;
	SM2_KEY m_sm2_key_public;
	char *m_password;
} HjkInfo;

void *hjk_init(void)
{
    HjkInfo *hjk_info = NULL;

    hjk_info = (HjkInfo *)malloc(sizeof(*hjk_info));
    if (NULL == hjk_info) {
        return NULL;
    }

    memset(hjk_info, 0, sizeof(*hjk_info));

	hjk_info->m_password = "123456";

    return (void *)hjk_info;
}

int hjk_gen_private_public_to_pem(void *_hjk_info)
{
    HjkInfo *hjk_info = NULL;
    if (NULL == _hjk_info) {
        return -1;
    }
    hjk_info = (HjkInfo *)_hjk_info;

	if (sm2_key_generate(&hjk_info->m_sm2_key_private) != 1) {
		fprintf(stderr, "error %d %s\n", __LINE__, __FUNCTION__);
		return -1;
	}

	if (sm2_private_key_info_encrypt_to_pem(&hjk_info->m_sm2_key_private, hjk_info->m_password, stdout) != 1) {
		fprintf(stderr, "error %d %s\n", __LINE__, __FUNCTION__);
		return -1;
	}

	if (sm2_public_key_info_to_pem(&hjk_info->m_sm2_key_private, stdout) != 1) {
		fprintf(stderr, "error %d %s\n", __LINE__, __FUNCTION__);
		return -1;
	}
    memcpy(&hjk_info->m_sm2_key_public, &hjk_info->m_sm2_key_private, sizeof(SM2_POINT));

    return 0;
}

int hjk_get_private_from_pem(void *_hjk_info, char *_private_pem_name)
{
    HjkInfo *hjk_info = NULL;
    if (NULL == _hjk_info) {
        return -1;
    }
    hjk_info = (HjkInfo *)_hjk_info;

	FILE *fp_pri_pem = NULL;
	unsigned char buf[512];
	unsigned char *p;
	size_t len;

	//if (!(keyfp = fopen(keyfile, "r"))) {
    if (NULL == (fp_pri_pem = fopen(_private_pem_name, "r"))) {
		fprintf(stderr, "error %d %s\n", __LINE__, __FUNCTION__);
        return -1;
    }

	if (sm2_private_key_info_decrypt_from_pem(&hjk_info->m_sm2_key_private, hjk_info->m_password, fp_pri_pem) != 1) {
		fprintf(stderr, "error %d %s\n", __LINE__, __FUNCTION__);
		return 1;
	}

	p = buf;
	len = 0;
	if (sm2_private_key_to_der(&hjk_info->m_sm2_key_private, &p, &len) != 1) {
		fprintf(stderr, "error %d %s\n", __LINE__, __FUNCTION__);
		return 1;
	}

    fprintf(stdout, "parse private key successful\n");
    return 0;
}

int hjk_get_public_from_pem(void *_hjk_info, char *_public_pem_name)
{
    HjkInfo *hjk_info = NULL;
    if (NULL == _hjk_info) {
        return -1;
    }
    hjk_info = (HjkInfo *)_hjk_info;
    FILE *pubkeyfp = NULL;
    if (!(pubkeyfp = fopen(_public_pem_name, "r"))) {
        fprintf(stderr, "open '%s' failure\n", _public_pem_name);
        return -1;
    }

    if (sm2_public_key_info_from_pem(&hjk_info->m_sm2_key_public, pubkeyfp) != 1) {
        fprintf(stderr, "parse public key failed\n");
        return -1;
    }

    fprintf(stdout, "parse public key successful\n");
    return 0;
}

int hjk_sign(void *_hjk_info, uint8_t *_pc_data, size_t _data_len, uint8_t *_pc_sign_data, size_t *_sign_data_len)
{
    HjkInfo *hjk_info = NULL;
    if (NULL == _hjk_info) {
        return -1;
    }
	SM2_SIGN_CTX sign_ctx;
    hjk_info = (HjkInfo *)_hjk_info;

	// sign without signer ID (and Z value)
	sm2_sign_init(&sign_ctx, &hjk_info->m_sm2_key_private, NULL, 0);
	sm2_sign_update(&sign_ctx, _pc_data, _data_len);
	sm2_sign_finish(&sign_ctx, _pc_sign_data, _sign_data_len);

    return 0;
}

int hjk_verify(void *_hjk_info, uint8_t *_pc_data, size_t _data_len, uint8_t *_pc_sign_data, size_t _sign_data_len)
{
    HjkInfo *hjk_info = NULL;
    if (NULL == _hjk_info) {
        return -1;
    }

    int ret = 0;
	SM2_SIGN_CTX sign_ctx;
    hjk_info = (HjkInfo *)_hjk_info;

	sm2_verify_init(&sign_ctx, &hjk_info->m_sm2_key_public, NULL, 0);
	sm2_verify_update(&sign_ctx, _pc_data, _data_len);
	ret = sm2_verify_finish(&sign_ctx, _pc_sign_data, _sign_data_len);

    return ret == 1 ? 0 : -1;
}

void hjk_uninit(void **_hjk_info)
{
    HjkInfo *hjk_info = NULL;

    if (NULL == _hjk_info) {
        return;
    }
    hjk_info = (HjkInfo *)*_hjk_info;

    free(*_hjk_info);
    *_hjk_info = NULL;

    return;
}

int main(int argc, char **argv)
{
    void *hjk_inst = NULL;
    hjk_inst = hjk_init();
    
    #if 0
    if (hjk_gen_private_public_to_pem(hjk_inst) < 0) {
        return -1;
    }
    #endif

    if (hjk_get_private_from_pem(hjk_inst, "sm2.pem") < 0) {
        return -1;
    }

    if (hjk_get_public_from_pem(hjk_inst, "sm2pub.pem") < 0) {
        return -1;
    }

    char sign_data[128];
    size_t sign_data_len;
    char *raw_data = "aaaaaaaaaaaaaaaaaaaaaaaaaaabbcccccccbbbbbbbbbbbbbbbbb";
    if (hjk_sign(hjk_inst, raw_data, strlen(raw_data), sign_data, &sign_data_len) < 0) {
		fprintf(stderr, "%d %s sign failed !\n", __LINE__, __FUNCTION__);
        return -1;
    }
	fprintf(stderr, "%d %s sign_data_len=%ld\n", __LINE__, __FUNCTION__, sign_data_len);

    if (hjk_verify(hjk_inst, raw_data, strlen(raw_data), sign_data, sign_data_len) < 0) {
		fprintf(stderr, "error %d %s\n", __LINE__, __FUNCTION__);
        return -1;
    }
	printf("verify success\n");

    hjk_uninit(&hjk_inst);

    return 0;
}
