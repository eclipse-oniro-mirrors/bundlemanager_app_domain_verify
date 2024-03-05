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

#ifndef APP_DOMAIN_VERIFY_EXTENSION_MGR_H
#define APP_DOMAIN_VERIFY_EXTENSION_MGR_H
#include <mutex>
#include "app_domain_verify_error.h"
#include "skill_uri.h"
#include "app_verify_base_info.h"
#include "inner_verify_status.h"
#include "bundle_verify_status_info.h"

namespace OHOS {
namespace AppDomainVerify {
class AppDomainVerifyExtensionMgr {
public:
    AppDomainVerifyExtensionMgr();
    virtual ~AppDomainVerifyExtensionMgr();
    ErrorCode CompleteVerifyRefresh(const BundleVerifyStatusInfo &bundleVerifyStatusInfo,
        const std::vector<InnerVerifyStatus> &statuses, int delaySeconds);
    ErrorCode SingleVerify(const AppVerifyBaseInfo &appVerifyBaseInfo, const std::vector<SkillUri> &skillUris);

private:
    bool Init();

private:
    static std::mutex sHandlerMutex;
    static void *sHandler;
};
}
}
#endif