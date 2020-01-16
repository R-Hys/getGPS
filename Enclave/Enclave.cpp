#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tae_service.h"


#define REPLAY_PROTECTED_SECRET_SIZE  32 
typedef struct _activity_log
{
    uint32_t release_version;
    uint32_t max_release_version;
}activity_log;

typedef struct _replay_protected_pay_load
{
    sgx_mc_uuid_t mc;
    uint32_t mc_value;
    float secret[REPLAY_PROTECTED_SECRET_SIZE][3];
    activity_log log;
}replay_protected_pay_load;

void ecall_array_user_check(int array[4])
{
    if (sgx_is_outside_enclave(array, 4 * sizeof(int)) != 1)
        abort();
    
    for (int i = 0; i < 4; i++) {
        assert(array[i] == i);
        array[i] = 3 - i;
    }
}

uint32_t init_sealed_policy(uint8_t* sealed_log, uint32_t sealed_log_size )
{
    uint32_t ret = 0;
    replay_protected_pay_load data2seal;
    memset(&data2seal, 0, sizeof(data2seal));
    uint32_t size = sgx_calc_sealed_data_size(0,sizeof(replay_protected_pay_load));
    printint(size);
    if(sealed_log_size != size) 
        return SGX_ERROR_INVALID_PARAMETER;
    do
    {
        for(int i=0; i<REPLAY_PROTECTED_SECRET_SIZE; ++i) for(int j=0;j<3;++j) data2seal.secret[i][j]=0.; // 初期化

        data2seal.log.release_version = 0;
        /* the secret can be updated for 5 times */
        data2seal.log.max_release_version = 
            REPLAY_PROTECTED_PAY_LOAD_MAX_RELEASE_VERSION;

        /*sealing the plaintext to ciphertext. The ciphertext can be delivered
        outside of enclave.*/
        ret = sgx_seal_data(0, NULL,sizeof(data2seal),(uint8_t*)&data2seal,
            sealed_log_size, (sgx_sealed_data_t*)sealed_log);
    } while (0);
    
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data2seal, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    return ret;
}

uint32_t update_sealed_policy(float data[3], uint8_t* sealed_log, uint32_t sealed_log_size)
{
    uint32_t ret = 0;
    replay_protected_pay_load data_unsealed;
    replay_protected_pay_load data2seal;
    if(sealed_log_size != sgx_calc_sealed_data_size(0,
        sizeof(replay_protected_pay_load))) 
        return SGX_ERROR_INVALID_PARAMETER;
    do
    {
        uint32_t unseal_length = sizeof(replay_protected_pay_load);

        ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_log, NULL, 0,
            (uint8_t*)&data_unsealed, &unseal_length);
        if(ret != SGX_SUCCESS) {
            if(ret==SGX_ERROR_INVALID_PARAMETER)
                printint(11111);
            return ret;
        }


        memcpy(&data2seal,&data_unsealed, sizeof(replay_protected_pay_load));

        /* next release versiona */
        data2seal.log.release_version++;
        /* release next data2seal.secret, here is a sample */
        for(int k=0;k<REPLAY_PROTECTED_SECRET_SIZE;++k){
            if(data2seal.secret[k][0]==0.){
                for(int i=0;i<3;++i) data2seal.secret[k][i]=data[i];
                break;
            }
        }

        /* seal the new log */
        ret = sgx_seal_data(0, NULL, sizeof(data2seal), (uint8_t*)&data2seal,
            sealed_log_size, (sgx_sealed_data_t*)sealed_log);
    } while (0);
    
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data_unsealed, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));

    /* remember to clear secret data after been used by memset_s */
    memset_s(&data2seal, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    // sgx_close_pse_session();
    return ret;
}


uint32_t show_sealed_policy(uint8_t* sealed_log, uint32_t sealed_log_size)
{
    uint32_t ret = 0;
    replay_protected_pay_load data_unsealed;
    replay_protected_pay_load data2seal;
    if(sealed_log_size != sgx_calc_sealed_data_size(0,
        sizeof(replay_protected_pay_load))) 
        return SGX_ERROR_INVALID_PARAMETER;
    do
    {
        uint32_t unseal_length = sizeof(replay_protected_pay_load);

        ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_log, NULL, 0,
            (uint8_t*)&data_unsealed, &unseal_length);
        if(ret != SGX_SUCCESS) {
            if(ret==SGX_ERROR_INVALID_PARAMETER)
                printint(11111);
            return ret;
        }


        memcpy(&data2seal,&data_unsealed, sizeof(replay_protected_pay_load));

        // /* next release versiona */
        // data2seal.log.release_version++;
        // /* release next data2seal.secret, here is a sample */
        // for(int k=0;k<REPLAY_PROTECTED_SECRET_SIZE;++k){
        //     if(data2seal.secret[k][0]=='\0'){
        //         for(int i=0;i<3;++i) data2seal.secret[k][i]=data[i];
        //         break;
        //     }
        // }
        printsecret(data2seal.secret);

        /* seal the new log */
        ret = sgx_seal_data(0, NULL, sizeof(data2seal), (uint8_t*)&data2seal,
            sealed_log_size, (sgx_sealed_data_t*)sealed_log);
    } while (0);
    
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data_unsealed, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));

    /* remember to clear secret data after been used by memset_s */
    memset_s(&data2seal, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    // sgx_close_pse_session();
    return ret;
}

uint32_t read_sealed_policy(uint8_t* sealed_log, uint32_t sealed_log_size)
{
    uint32_t ret = 0;
    replay_protected_pay_load data_unsealed;
    replay_protected_pay_load data2seal;
    if(sealed_log_size != sgx_calc_sealed_data_size(0,
        sizeof(replay_protected_pay_load))) 
        return SGX_ERROR_INVALID_PARAMETER;
    do
    {
        uint32_t unseal_length = sizeof(replay_protected_pay_load);

        ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_log, NULL, 0,
            (uint8_t*)&data_unsealed, &unseal_length);
        if(ret != SGX_SUCCESS) {
            if(ret==SGX_ERROR_INVALID_PARAMETER)
                printint(11111);
            return ret;
        }


        memcpy(&data2seal,&data_unsealed, sizeof(replay_protected_pay_load));

        /* seal the new log */
        ret = sgx_seal_data(0, NULL, sizeof(data2seal), (uint8_t*)&data2seal,
            sealed_log_size, (sgx_sealed_data_t*)sealed_log);
    } while (0);
    
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data_unsealed, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));

    /* remember to clear secret data after been used by memset_s */
    memset_s(&data2seal, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    // sgx_close_pse_session();
    return ret;
}