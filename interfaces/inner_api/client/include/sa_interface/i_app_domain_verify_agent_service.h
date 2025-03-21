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
#ifndef I_APP_DOMAIN_VERIFY_AGENT_SERVICE_H
#define I_APP_DOMAIN_VERIFY_AGENT_SERVICE_H
#include <string>

#include "app_domain_verify_hilog.h"
#include "iremote_broker.h"
#include "skill_uri.h"
#include "want.h"
#include "ability_info.h"
#include "inner_verify_status.h"
#include "app_verify_base_info.h"
#include "bundle_verify_status_info.h"
#include "zidl/i_convert_callback.h"

namespace OHOS {
namespace AppDomainVerify {
class IAppDomainVerifyAgentService : public IRemoteBroker {
public:
    virtual void SingleVerify(const AppVerifyBaseInfo& appVerifyBaseInfo, const VerifyResultInfo& verifyResultInfo) {};
    virtual void ConvertToExplicitWant(OHOS::AAFwk::Want& implicitWant, sptr<IConvertCallback>& callback) {};
    virtual int CommonTransact(uint32_t opcode, const std::string& request, std::string& response)
    {
        return 0;
    };
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appDomainVerify.IAppDomainVerifyAgentService");
};
}  // namespace AppDomainVerify
}  // namespace OHOS

#endif