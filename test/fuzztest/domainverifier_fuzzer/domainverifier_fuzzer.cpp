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
#include "securec.h"

using namespace OHOS::AppDomainVerify;
using namespace OHOS::NetStack::HttpClient;

namespace OHOS {
    /**
     * @brief 策略1: 使用纯随机数据进行测试
     * 主要测试 JSON 解析器在面对畸形数据时的鲁棒性，防止崩溃。
     */
    void FuzzVerifyHostWithRawData(const uint8_t* data, size_t size) {
         if (size < 4) return;
         
         // 随机生成 HTTP 响应码 (0-599)
         ResponseCode responseCode = static_cast<ResponseCode>(data[0] % 600);
         
         // 剩余数据全部作为 JSON 字符串
         std::string assetJsonsStr(reinterpret_cast<const char*>(data + 4), size - 4);
         
         // 构造一个简单的 BaseInfo
         AppVerifyBaseInfo appVerifyBaseInfo;
         appVerifyBaseInfo.bundleName = "com.random.test"; 
         
         DomainVerifier::VerifyHost(responseCode, assetJsonsStr, appVerifyBaseInfo);
    }

    /**
     * @brief 策略2: 使用模板构造合法 JSON 结构进行测试
     * 确保能通过 JSON 解析，深入覆盖 VerifyHost 内部的业务逻辑分支（如包名比对、指纹验证）。
     */
    void FuzzVerifyHostWithTemplate(const uint8_t* data, size_t size) {
        if (size == 0) return;
        
        // 将随机数据转换为字符串，用于填充字段
        std::string fuzzString(reinterpret_cast<const char*>(data), size);
        
        // 构造合法的 JSON 模板
        // 结构参考自: agent_constants.h 和 asset_json_obj.h
        // 这里构造了一个包含 applinking -> apps 数组的结构，确保解析器能读到内容
        std::string bundleName = "com.fuzz.test";
        std::string jsonStr = 
            "{"
            "  \"applinking\": {"
            "    \"apps\": ["
            "      {"
            "        \"bundleName\": \"" + bundleName + "\","
            "        \"appIdentifier\": \"id_" + fuzzString + "\","
            "        \"fingerprint\": \"" + fuzzString + "\""
            "      }"
            "    ]"
            "  }"
            "}";
        
        AppVerifyBaseInfo info;
        info.bundleName = bundleName;   // 1. 确保 BundleName 匹配成功，进入指纹校验逻辑
        info.appIdentifier = "id_" + fuzzString;
        
        // 2. 指纹匹配测试：
        // size 为偶数时，指纹完全匹配 -> 预期验证成功
        // size 为奇数时，指纹不匹配 -> 预期验证失败
        if (size % 2 == 0) {
            info.fingerprint = fuzzString;
        } else {
            info.fingerprint = "mismatch_" + fuzzString;
        }

        // 3. 随机状态码测试
        // 偶数时模拟 HTTP 200 OK，奇数时模拟 HTTP 404/500 等错误
        ResponseCode code = (size % 2 == 0) ? ResponseCode::OK : ResponseCode::NOT_FOUND;

        DomainVerifier::VerifyHost(code, jsonStr, info);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        // 结合两种策略，最大化测试覆盖面
        
        // 1. 纯随机数据 (概率 50%)
        if (size % 2 != 0) {
            FuzzVerifyHostWithRawData(data, size);
        }
        
        // 2. 结构化模板数据 (概率 50%)
        if (size % 2 == 0) {
            FuzzVerifyHostWithTemplate(data, size);
        }
        
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

