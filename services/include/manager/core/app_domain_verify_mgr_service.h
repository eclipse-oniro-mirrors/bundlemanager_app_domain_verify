/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef APP_DOMAIN_VERIFY_MGR_SERVICE_H
#define APP_DOMAIN_VERIFY_MGR_SERVICE_H

#include "app_domain_verify_mgr_service_stub.h"
#include "inner_verify_status.h"
#include "skill_uri.h"
#include "system_ability.h"
#include "i_app_domain_verify_mgr_service.h"
#include "i_app_domain_verify_agent_service.h"

namespace OHOS {
namespace AppDomainVerify {
class AppDomainVerifyMgrService : public SystemAbility, public AppDomainVerifyMgrServiceStub {
    DECLARE_SYSTEM_ABILITY(AppDomainVerifyMgrService);

public:
    API_EXPORT AppDomainVerifyMgrService();
    API_EXPORT virtual ~AppDomainVerifyMgrService();
    void VerifyDomain(const std::string &appIdentifier, const std::string &bundleName, const std::string &fingerprint,
        const std::vector<SkillUri> &skillUris) override;
    bool ClearDomainVerifyStatus(const std::string &appIdentifier, const std::string &bundleName) override;
    bool FilterAbilities(const OHOS::AAFwk::Want &want,
        const std::vector<OHOS::AppExecFwk::AbilityInfo> &originAbilityInfos,
        std::vector<OHOS::AppExecFwk::AbilityInfo> &filtedAbilityInfos) override;
    bool QueryDomainVerifyStatus(const std::string &bundleName,
        DomainVerifyStatus &domainVerificationState) override;
    bool QueryAllDomainVerifyStatus(BundleVerifyStatusInfo &bundleVerifyStatusInfo) override;
    bool SaveDomainVerifyStatus(const std::string &bundleName, const VerifyResultInfo &verifyResultInfo) override;
    
protected:
    void OnStart() override;
    void OnStop() override;

private:
    bool IsWantImplicit(const OHOS::AAFwk::Want &want);
};
}  // namespace AppDomainVerify
}  // namespace OHOS
#endif  // APP_DOMAIN_VERIFY_SERVICE_H