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

#include "appdomainverifytaskmgr_fuzzer.h"

#include "app_domain_verify_task_mgr.h"
#include "verify_http_task.h"
#include "i_verify_task.h"
#include <string>
#include <memory>

using namespace OHOS::AppDomainVerify;

class MockVerifyTask : public IVerifyTask {
public:
    void OnPostVerify(const std::string& uri, const NetStack::HttpClient::HttpClientResponse& response) override {}
    void OnSaveVerifyResult() override {}
    bool OnPreRequest(NetStack::HttpClient::HttpClientRequest& request, const std::string& uri) override { return true; }
    const HostVerifyStatusMap& GetUriVerifyMap() override { return map_; }
    TaskType GetType() override { return static_cast<TaskType>(1); }
    HostVerifyStatusMap map_;
};

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        std::string testString(reinterpret_cast<const char*>(data), size);
        std::string testUri = "https://" + testString;
        
        // Construct a MockVerifyTask
        auto mockTask = std::make_shared<MockVerifyTask>();
        // Construct VerifyHttpTask with the mock
        auto httpTask = std::make_shared<VerifyHttpTask>(testUri, mockTask);
        
        // Fuzz AddTask
        AppDomainVerifyTaskMgr::GetInstance()->AddTask(testString, httpTask);

        // Fuzz HasTask
        AppDomainVerifyTaskMgr::GetInstance()->HasTask(testString);
        
        // Fuzz RemoveTask
        AppDomainVerifyTaskMgr::GetInstance()->RemoveTask(testString);

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

