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

#include "whitelistconfigmgr_fuzzer.h"

#include "white_list_config_mgr.h"
#include <string>
#include <unordered_set>
#include <vector>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        // Split data for updating whitelist and checking
        std::string input(reinterpret_cast<const char*>(data), size);
        std::string updateStr = input.substr(0, size / 2);
        std::string checkStr = input.substr(size / 2);

        AppDomainVerify::WhiteListConfigMgr mgr;
        
        // Fuzz UpdateWhiteList
        std::unordered_set<std::string> whiteList;
        whiteList.insert(updateStr);
        // Add some hardcoded ones to ensure hits are possible if checkStr matches
        whiteList.insert("example.com");
        mgr.UpdateWhiteList(whiteList);

        // Fuzz IsInWhiteList logic
        mgr.IsInWhiteList(checkStr);
        mgr.IsInWhiteList("example.com");

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

