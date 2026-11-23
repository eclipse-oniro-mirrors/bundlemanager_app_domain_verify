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

#include "domainurlutil_fuzzer.h"

#include <string>
#include "domain_url_util.h"

using namespace OHOS::AppDomainVerify;

namespace OHOS {
    void TestUrlUtil(const std::string& url)
    {
        UrlUtil::IsValidAppDomainVerifyHost(url);
        UrlUtil::IsValidUrl(url);
        UrlUtil::GetHost(url);
        UrlUtil::GetScheme(url);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        std::string rawData(reinterpret_cast<const char*>(data), size);

        // 1. Raw Data Test
        TestUrlUtil(rawData);

        // 2. Construct URL with common Scheme to cover Scheme check inside IsValidUrl
        // Many URL parsing logics are triggered by Scheme
        std::string httpUrl = "http://" + rawData;
        TestUrlUtil(httpUrl);

        std::string httpsUrl = "https://" + rawData;
        TestUrlUtil(httpsUrl);

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

