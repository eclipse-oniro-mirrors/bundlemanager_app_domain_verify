/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef APP_DOMAIN_VERIFY_MOC_VERIFY_TASK_H
#define APP_DOMAIN_VERIFY_MOC_VERIFY_TASK_H
#include "verify_task.h"
#include <gmock/gmock.h>
namespace OHOS::AppDomainVerify {
class MocVerifyTask : public VerifyTask {
public:
    MocVerifyTask(OHOS::AppDomainVerify::TaskType type, const AppVerifyBaseInfo& appVerifyBaseInfo,
        const std::vector<SkillUri>& skillUris)
        : VerifyTask(type, appVerifyBaseInfo, skillUris)
    {
    }
    MOCK_METHOD(bool, SaveDomainVerifyStatus, (const std::string& bundleName, const VerifyResultInfo& verifyResultInfo),
        (override));
};
}
#endif  // APP_DOMAIN_VERIFY_MOC_VERIFY_TASK_H
