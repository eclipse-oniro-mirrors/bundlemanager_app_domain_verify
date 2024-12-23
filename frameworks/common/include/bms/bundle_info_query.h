/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef APP_DOMAIN_VERIFY_BUNDLE_INFO_QUERY_H
#define APP_DOMAIN_VERIFY_BUNDLE_INFO_QUERY_H

#include "bundlemgr/bundle_mgr_interface.h"

namespace OHOS {
namespace AppDomainVerify {
using Want = OHOS::AAFwk::Want;
using AbilityInfo = OHOS::AppExecFwk::AbilityInfo;
constexpr const char* ACTION_VIEW_DATA = "ohos.want.action.viewData";
constexpr const char* ENTITY_BROWSER = "entity.system.browsable";
class BundleInfoQuery {
public:
    static bool GetBundleInfo(const std::string& bundleName, std::string& appIdentifier, std::string& fingerprint);
    static bool GetBundleNameForUid(int uid, std::string& bundleName);
    static bool GetBundleAbilityInfos(const std::string& bundleName, std::vector<AbilityInfo>& abilityInfos);

private:
    static sptr<AppExecFwk::IBundleMgr> GetBundleMgrProxy();
    static int32_t GetCurrentAccountId();
    BundleInfoQuery(){};
    ~BundleInfoQuery() = default;
};
}
}

#endif