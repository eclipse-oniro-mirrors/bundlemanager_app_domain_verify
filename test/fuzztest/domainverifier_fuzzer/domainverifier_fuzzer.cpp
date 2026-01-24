/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "domainverifier_fuzzer.h"

#include <string>
#include <vector>
#include "domain_verifier.h"
#include "app_verify_base_info.h"
#include "http_client.h"

using namespace OHOS::AppDomainVerify;
using namespace OHOS::NetStack::HttpClient;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 4) { // 需要至少4个字节用于构造元数据
            return false;
        }

        // 使用前4个字节来构造一些随机参数
        // data[0]: 用来随机选择 ResponseCode
        // data[1]: 用来决定 appIdentifier 的长度 (简单的模运算)
        // data[2]: 用来决定 bundleName 的长度
        // data[3]: 用来决定 finger print 的长度

        ResponseCode responseCode = static_cast<ResponseCode>(data[0] % 600); // 随机生成一个 HTTP 状态码
        
        size_t jsonStrLen = size - 4;
        std::string assetJsonsStr(reinterpret_cast<const char*>(data + 4), jsonStrLen);

        AppVerifyBaseInfo appVerifyBaseInfo;
        
        // 构造随机的 AppVerifyBaseInfo
        std::string appIdentifier = "test_app_identifier_" + std::to_string(data[1]);
        std::string bundleName = "com.test.bundle" + std::to_string(data[2]);
        std::string fingerprint = "test_fingerprint_" + std::to_string(data[3]);

        appVerifyBaseInfo.appIdentifier = appIdentifier;
        appVerifyBaseInfo.bundleName = bundleName;
        appVerifyBaseInfo.fingerprint = fingerprint;

        DomainVerifier::VerifyHost(responseCode, assetJsonsStr, appVerifyBaseInfo);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

