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
#ifndef APP_DOMAIN_VERIFY_MANAGER_API_EVENT_REPORTER_H
#define APP_DOMAIN_VERIFY_MANAGER_API_EVENT_REPORTER_H

#include <string>
namespace OHOS::AppDomainVerify::Dfx {
constexpr int32_t API_SUCCESS = 0;
constexpr int32_t API_FAIL = 1;
class ApiEventReporter {
public:
    explicit ApiEventReporter(const std::string& apiName);
    ~ApiEventReporter() = default;
    void WriteEndEvent(const int result, const int32_t errCode);

private:
    int64_t AddProcessor();

private:
    std::string transId_;
    std::string apiName_;
    int64_t startTime_;
};
}
#endif  // APP_DOMAIN_VERIFY_MANAGER_API_EVENT_REPORTER_H
