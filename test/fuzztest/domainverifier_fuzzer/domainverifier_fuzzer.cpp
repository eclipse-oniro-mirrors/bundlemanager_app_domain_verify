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
     * @brief Strategy 1: Test with pure random data.
     * Mainly tests the robustness of the JSON parser against malformed data to prevent crashes.
     */
    void FuzzVerifyHostWithRawData(const uint8_t* data, size_t size)
    {
        constexpr int32_t minSize = 4;
        constexpr int32_t responseCodeRange = 600;

        if (size < minSize) {
            return;
        }

        // Randomly generate HTTP response code (0-599)
        ResponseCode responseCode = static_cast<ResponseCode>(data[0] % responseCodeRange);

        // Use the remaining data as a JSON string
        std::string assetJsonsStr(reinterpret_cast<const char*>(data + minSize), size - minSize);

        // Construct a simple BaseInfo
        AppVerifyBaseInfo appVerifyBaseInfo;
        appVerifyBaseInfo.bundleName = "com.random.test";

        DomainVerifier::VerifyHost(responseCode, assetJsonsStr, appVerifyBaseInfo);
    }

    /**
     * @brief Strategy 2: Test with a template constructing a valid JSON structure.
     * Ensures that the JSON parser passes and deeply covers the business logic branches within VerifyHost
     * (such as bundle name comparison and fingerprint verification).
     */
    void FuzzVerifyHostWithTemplate(const uint8_t* data, size_t size)
    {
        if (size == 0) {
            return;
        }

        // Convert random data to string for filling fields
        std::string fuzzString(reinterpret_cast<const char*>(data), size);

        // Construct a valid JSON template
        // Structure based on: agent_constants.h and asset_json_obj.h
        // Construct a structure containing applinking -> apps array to ensure the parser can read content
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
        info.bundleName = bundleName;   // 1. Ensure BundleName matches to enter fingerprint verification logic
        info.appIdentifier = "id_" + fuzzString;

        // 2. Fingerprint matching test:
        // When size is even, fingerprint matches completely -> expected verification success
        // When size is odd, fingerprint mismatch -> expected verification failure
    constexpr size_t modTwo = 2;
    if (size % modTwo == 0) {
        }

        // 3. Random status code test
        // Even: simulate HTTP 200 OK; Odd: simulate HTTP 404/500 errors
        ResponseCode code = (size % 2 == 0) ? ResponseCode::OK : ResponseCode::NOT_FOUND;

        DomainVerifier::VerifyHost(code, jsonStr, info);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        // Combine two strategies to maximize test coverage
    constexpr size_t modTwo = 2;

    // 1. Pure random data (50% probability)
    if (size % modTwo != 0) {
        FuzzVerifyHostWithRawData(data, size);
    }

    // 2. Structured template data (50% probability)
    if (size % modTwo == 0) {
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

