
#include <sgx_tseal.h>
#include "Seal_t.h"
#include <memory>
#include <sgx_pcl_guid.h>

sgx_status_t provision_key_mock (uint8_t* key_ptr, uint32_t key_len )
{
    if ( (NULL == key_ptr) || (SGX_AESGCM_KEY_SIZE != key_len))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    const uint8_t key[SGX_AESGCM_KEY_SIZE] = 
        { 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99 };
    memcpy (key_ptr, key, key_len);
    return SGX_SUCCESS;
}

sgx_status_t provision_key( uint8_t* key_ptr, uint32_t key_len )
{
    return provision_key_mock(key_ptr, key_len);
}

size_t ecall_get_sealed_blob_size()
{
    return (size_t)sgx_calc_sealed_data_size ( SGX_PCL_GUID_SIZE, SGX_AESGCM_KEY_SIZE );
}

sgx_status_t ecall_generate_sealed_blob(uint8_t* sealed_blob, size_t sealed_blob_size)
{
    if ((NULL == sealed_blob) || (ecall_get_sealed_blob_size() != sealed_blob_size)){
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t retstatus = SGX_ERROR_UNEXPECTED;
    uint8_t key[SGX_AESGCM_KEY_SIZE] = { 0 };

    retstatus = provision_key(key, SGX_AESGCM_KEY_SIZE);
    if (retstatus != SGX_SUCCESS ){
        return retstatus;
    }
    
    retstatus = sgx_seal_data (
        SGX_PCL_GUID_SIZE,                 // AAD size
        g_pcl_guid,                        // AAD
        SGX_AESGCM_KEY_SIZE,               // Key len
        key,                               // Key
        (uint32_t)sealed_blob_size,                  // Resulting blob size
        (sgx_sealed_data_t*)sealed_blob ); // Resulting blob

    memset(key, 0,SGX_AESGCM_KEY_SIZE); 
    return retstatus;
}