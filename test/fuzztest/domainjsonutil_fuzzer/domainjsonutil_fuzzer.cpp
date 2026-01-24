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

#include "domainjsonutil_fuzzer.h"

#include <string>
#include <vector>
#include "domain_json_util.h"
#include "asset_json_obj.h"

using namespace OHOS::AppDomainVerify;

namespace OHOS {
    void FuzzJsonUtilWithRawData(const uint8_t* data, size_t size)
    {
        std::string jsonStr(reinterpret_cast<const char*>(data), size);
        AssetJsonObj assetJsonObj;
        JsonUtil::Parse(jsonStr, assetJsonObj);
    }

    void FuzzJsonUtilWithTemplate(const uint8_t* data, size_t size)
    {
        if (size == 0) {
            return;
        }
        std::string fuzzString(reinterpret_cast<const char*>(data), size);

        // Construct a JSON structure containing core fields to ensure reaching object mapping logic
        std::string jsonStr =
            "{"
            "  \"applinking\": {"
            "    \"apps\": ["
            "      {"
            "        \"bundleName\": \"com.example.test\","
            "        \"appIdentifier\": \"" + fuzzString + "\","
            "        \"fingerprint\": \"" + fuzzString + "\""
            "      }"
            "    ]"
            "  }"
            "}";

        AssetJsonObj assetJsonObj;
        JsonUtil::Parse(jsonStr, assetJsonObj);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        constexpr int modTwo = 2;
        // 1. Raw Data Mode: Test parser robustness against crashes
        // If odd, use raw content
        if (size % modTwo != 0) {
            FuzzJsonUtilWithRawData(data, size);
        }

        // 2. Template Mode: Test business object mapping logic
        // If even, switch to template mode
        if (size % modTwo == 0) {
            FuzzJsonUtilWithTemplate(data, size);
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

