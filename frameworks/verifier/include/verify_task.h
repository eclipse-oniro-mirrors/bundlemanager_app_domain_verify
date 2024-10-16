/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef APP_DOMAIN_VERIFY_VERIFY_TASK_H
#define APP_DOMAIN_VERIFY_VERIFY_TASK_H
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include "bundle_verify_status_info.h"
#include "i_verify_task.h"
#include "http_client_response.h"
#include "app_verify_base_info.h"
#include "inner_verify_status.h"
#include "dfx/app_domain_verify_hisysevent.h"
#include "skill_uri.h"
#include "app_domain_verify_mgr_client.h"
#include "i_http_task.h"

namespace OHOS {
namespace AppDomainVerify {
using StatusHandleFunc  = std::function<bool(std::string, int)>;
class VerifyTask : public IVerifyTask {
public:
    void OnPostVerify(const std::string &uri, const OHOS::NetStack::HttpClient::HttpClientResponse &response) override;
    void OnSaveVerifyResult() override;
    bool OnPreRequest(OHOS::NetStack::HttpClient::HttpClientRequest &request, const std::string &uri) override;
    OHOS::AppDomainVerify::TaskType GetType() override;
    const HostVerifyStatusMap &GetUriVerifyMap() override;

    VerifyTask(OHOS::AppDomainVerify::TaskType type, const AppVerifyBaseInfo &appVerifyBaseInfo,
        const VerifyResultInfo& verifyResultInfo);
    void InitUriUnVerifySetMap(const VerifyResultInfo& verifyResultInfo);
    void Execute();
protected:
    int64_t CalcRetryDuration(int verifyCnt);
    bool HandleFailureClientError(std::string verifyTime, int verifyCnt);
    bool HandleStateSuccess(std::string verifyTime, int verifyCnt);
    bool HandleForbiddenForever(std::string verifyTime, int verifyCnt);
    bool IsNeedRetry(const std::tuple<InnerVerifyStatus, std::string, int>& info);
    OHOS::AppDomainVerify::TaskType& GetTaskType();
    AppVerifyBaseInfo& GetAppVerifyBaseInfo();
private:
    void UpdateVerifyResultInfo(const std::string& uri, InnerVerifyStatus status);
    virtual bool SaveDomainVerifyStatus(const std::string& bundleName, const VerifyResultInfo& verifyResultInfo);
    OHOS::AppDomainVerify::TaskType type_;
    AppVerifyBaseInfo appVerifyBaseInfo_;
    std::unordered_set<std::string> unVerifiedSet_;
    VerifyResultInfo verifyResultInfo_;
    std::unordered_map<InnerVerifyStatus, StatusHandleFunc> staHandlerMap;
};
}
}
#endif  // APP_DOMAIN_VERIFY_VERIFY_TASK_H
