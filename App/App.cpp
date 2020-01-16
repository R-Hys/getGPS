#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "Seal_u.h"

#define SEAL_FILENAME             "Seal.signed.so"
#define SEALED_KEY_FILE_NAME     "sealed_key.bin"
#define TOKEN_FILENAME            "enclave.token"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

using namespace std;

class GPS
{
public:
    GPS();
    
    uint32_t init(uint8_t*  stored_sealed_activity_log);
    uint32_t init();

    uint32_t update(float data[3], uint8_t*  stored_sealed_activity_log);
    uint32_t update(float data[3]);

    uint32_t show(uint8_t*  stored_sealed_activity_log);
    uint32_t show();

    uint32_t read(FILE *fp,uint8_t* stored_sealed_activity_log);
    uint32_t read(FILE *fp);

    uint32_t write(uint8_t*  stored_sealed_activity_log);
    uint32_t write();
    
    static const uint32_t sealed_activity_log_length = SEALED_REPLAY_PROTECTED_PAY_LOAD_SIZE;
private:
    uint8_t  sealed_activity_log[sealed_activity_log_length];
    sgx_enclave_id_t enclave_id;

};

void printsecret(float secret[32][3]){
    cout<<"------\n";
    for(int i=0; i<5; ++i) {
        for(int j=0;j<3;++j) 
            cout<<secret[i][j]<<" ";
        cout<<endl;
    } 
    cout<<"------\n";
}

void printint(uint32_t num){
    cout<<num<<endl;
}

GPS::GPS(): enclave_id(global_eid)
{
    // 
}

uint32_t GPS:: init(uint8_t*  stored_sealed_activity_log)
{
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = 0;
    sgx_ret = init_sealed_policy(enclave_id, &enclave_ret,
        (uint8_t *)stored_sealed_activity_log, sealed_activity_log_length);
    if (sgx_ret)
    {
        cerr<<"call init_sealed_policy fail, error code = 0x"<< hex<< sgx_ret
            <<endl;
        return sgx_ret;
    } 
    if (enclave_ret)
    {
        cerr<<"cannot init_sealed_policy, function return fail, error code ="
            "0x"<< hex<< enclave_ret <<endl;
        return enclave_ret;
    }
    return 0;
}

uint32_t GPS:: init()
{
    return init(sealed_activity_log);
}

uint32_t GPS:: update(float data[3], uint8_t*  stored_sealed_activity_log)
{
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = 0;
    sgx_ret = update_sealed_policy(enclave_id, &enclave_ret, data,
        (uint8_t *)stored_sealed_activity_log, sealed_activity_log_length);
    if (sgx_ret)
    {
        cerr<<"call update_sealed_policy fail, error code = 0x"<< hex<< sgx_ret
            <<endl;
        return sgx_ret;
    } 
    if (enclave_ret)
    {
        cerr<<"cannot update_sealed_policy, function return fail, error code ="
            "0x"<< hex<< enclave_ret <<endl;
        return enclave_ret;
    }
    return 0;
}

uint32_t GPS:: update(float data[3])
{
    return update(data,sealed_activity_log);
}

uint32_t GPS:: show(uint8_t*  stored_sealed_activity_log)
{
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = 0;
    sgx_ret = show_sealed_policy(enclave_id, &enclave_ret,
        (uint8_t *)stored_sealed_activity_log, sealed_activity_log_length);
    if (sgx_ret)
    {
        cerr<<"call show_sealed_policy fail, error code = 0x"<< hex<< sgx_ret
            <<endl;
        return sgx_ret;
    } 
    if (enclave_ret)
    {
        cerr<<"cannot show_sealed_policy, function return fail, error code ="
            "0x"<< hex<< enclave_ret <<endl;
        return enclave_ret;
    }
    return 0;
}

uint32_t GPS:: show()
{
    return show(sealed_activity_log);
}

uint32_t GPS:: read(FILE* fp,uint8_t*  stored_sealed_activity_log)
{
    // FILE* fp=fopen("encgps.dat","rb");
    fread(stored_sealed_activity_log,sizeof(uint8_t),SEALED_REPLAY_PROTECTED_PAY_LOAD_SIZE,fp);
    
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = 0;
    sgx_ret = read_sealed_policy(enclave_id, &enclave_ret,
        (uint8_t *)stored_sealed_activity_log, sealed_activity_log_length);
    if (sgx_ret)
    {
        cerr<<"call read_sealed_policy fail, error code = 0x"<< hex<< sgx_ret
            <<endl;
        return sgx_ret;
    } 
    if (enclave_ret)
    {
        cerr<<"cannot read_sealed_policy, function return fail, error code ="
            "0x"<< hex<< enclave_ret <<endl;
        return enclave_ret;
    }
    return 0;
}

uint32_t GPS:: read(FILE* fp)
{
    return read(fp,sealed_activity_log);
}

uint32_t GPS:: write(uint8_t*  stored_sealed_activity_log)
{
    FILE* fp=fopen("encgps.dat","wb");
    fwrite(stored_sealed_activity_log,sizeof(uint8_t),SEALED_REPLAY_PROTECTED_PAY_LOAD_SIZE,fp);
    fclose(fp);

    return 0;
}

uint32_t GPS:: write()
{
    return write(sealed_activity_log);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
sgx_status_t initialize_enclave(char *file_name, sgx_enclave_id_t* eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    size_t read_num = 0;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
#ifdef SGX_USE_PCL      
    printf("Use PCL..\n");
    bool open_seal_enclave = true;
    uint8_t* sealed_blob = NULL;
    FILE *fsealp = fopen(SEALED_KEY_FILE_NAME, "rb");
    size_t sealed_blob_size = 0;
    if(NULL != fsealp) // seal鍵が存在している場合
    {   
        // Read file size:
        fseek(fsealp, 0L, SEEK_END);
        sealed_blob_size = ftell(fsealp);
        fseek(fsealp, 0L, SEEK_SET);
        // Read file into buffer:
        sealed_blob = new uint8_t[sealed_blob_size];
        read_num = fread(sealed_blob, 1, sealed_blob_size, fsealp);
        if ( read_num != sealed_blob_size )
        {
            printf ( "Warning: Failed to read sealed blob.\n" );
        }
        else
        {
            open_seal_enclave = false;
        }
        fclose(fsealp);
    }
    if (true == open_seal_enclave) // seal鍵が存在していない場合
    {
        printf ("Open Seal Enclave: %s\n", SEAL_FILENAME );
        sgx_enclave_id_t seal_eid = 0;
        ret = sgx_create_enclave(
            SEAL_FILENAME, 
            SGX_DEBUG_FLAG, 
            NULL, 
            NULL, 
            &seal_eid, 
            NULL);                 // enclave領域の作成
        if (SGX_SUCCESS != ret)    // 作成に失敗でエラーを返す
        {
            // print_error_message(ret); 
            return ret;
        }        
        ret = ecall_get_sealed_blob_size(seal_eid, &sealed_blob_size);  // Seal.cpp(.edl)からの呼び出し．sealed_blob_sizeの確保．
        if (ret != SGX_SUCCESS || UINT32_MAX == sealed_blob_size)  // サイズの確保失敗 or サイズが小さい  でエラー
        {
            printf("ecall_get_sealed_blob_size: ret = %d, sealed_blob_size = %ld\n", ret, sealed_blob_size);
            sgx_destroy_enclave(seal_eid);
            return ret;
        }
        printf("ecall_get_sealed_blob_size: ret = %d, sealed_blob_size = %ld\n", ret, sealed_blob_size);
        sealed_blob = new uint8_t[sealed_blob_size];  // sealされたデータの保持
        sgx_status_t gret = SGX_ERROR_UNEXPECTED;
        ret = ecall_generate_sealed_blob(seal_eid, &gret, sealed_blob, sealed_blob_size);  // sealed_blobの作成
        if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != gret))   // 作成の失敗でエラー
        {
            printf("ecall_generate_sealed_blob: ret = %d, gret = 0x%x\n", ret, gret);
            sgx_destroy_enclave(seal_eid);
            delete sealed_blob;
            return ret;
        }
        sgx_destroy_enclave(seal_eid);  // seal_blobの作成で一通りのenclaveでの作業が終了するのでこのenclaveはデストラクトする
        fsealp = fopen(SEALED_KEY_FILE_NAME, "wb");  // SEALED_KEY_FILE_NAMEには何も入っていないのでsealed_blobを書き込むことで次回以降も同じ領域を使える
        if(NULL != fsealp)
        {
            fwrite(sealed_blob, 1, sealed_blob_size, fsealp);
            fclose(fsealp);
        }
    }
    ret = sgx_create_encrypted_enclave(file_name, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL, sealed_blob); // sealed_blobで暗号化されたenclave領域の作成
    delete sealed_blob;
#else  // SGX_USE_PCL
    ret = sgx_create_enclave(file_name, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
#endif // SGX_USE_PCL
    return ret;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave(ENCLAVE_FILENAME, &global_eid) < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* user_check */
    int arr1[4] = {0, 1, 2, 3};
    ret = ecall_array_user_check(global_eid, arr1);
    if (ret != SGX_SUCCESS)
        abort();
    // for(int i=0; i<4; ++i){
    //     printf("%d ",arr1[i]);
    // }
    // printf("\n");
    

    GPS gps;
    uint32_t result=0;
    FILE *fp;
    float buf[3]={0};
    uint8_t* encbuf;

    /*
     * encgps.datが空であれば初めての処理なので初期化
     * そうでなければsealed_logから読み込む作業が必要
     */
    fp=fopen("encgps.dat","rb");
    if(fp==NULL){
        // printf("init start..\n");
        // fp=fopen("pastgps.dat","r");
        // if(fp==NULL) {
        //     printf("cannot read file:\"past_gps.dat\"\n");
        //     sgx_destroy_enclave(global_eid);
        //     return -1;
        // }
        // if(fscanf(fp,"%f,%f,%f",&buf[0],&buf[1],&buf[2]) == EOF){
        //     printf("file is empty:\"past_gps.dat\"\n");
        //     sgx_destroy_enclave(global_eid);
        //     return -1;
        // }
        result=gps.init();
        if(!result) printf("Init Done.\n");
    }
    else{
        result=gps.read(fp);
        if(!result) printf("Read Done.\n");
    }

    gps.show();

    fp=fopen("newgps.dat","r");
    if(fp==NULL) {
        printf("cannot read file:\"new_gps.dat\"\n");
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    if(fscanf(fp,"%f,%f,%f",&buf[0],&buf[1],&buf[2]) == EOF){
        printf("file is empty:\"new_gps.dat\"\n");
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    result=gps.update(buf);
    if(!result) printf("Update Done.\n");

    gps.show();

    result=gps.write();
    if(!result) printf("Write Done.\n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    // printf("Info: SampleEnclave successfully returned.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();

    return 0;
}
