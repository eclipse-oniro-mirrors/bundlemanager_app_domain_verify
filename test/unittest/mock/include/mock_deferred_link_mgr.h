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

#ifndef APP_DOMAIN_VERIFY_MOCK_DEFERRED_LINK_MGR_H
#define APP_DOMAIN_VERIFY_MOCK_DEFERRED_LINK_MGR_H
#include <string>
#include <memory>
#include <gmock/gmock.h>
#include "deferred_link_mgr.h"
namespace OHOS::AppDomainVerify {
class MocIDeferredLinkMgr {
public:
    MocIDeferredLinkMgr() = default;
    virtual ~MocIDeferredLinkMgr() = default;
    virtual void PutDeferredLink(const DeferredLinkInfo& info) = 0;
    virtual std::string GetDeferredLink(const std::string& bundleName, const std::vector<std::string>& domains) = 0;
    virtual void RemoveDeferredLink(const DeferredLinkInfo& info) = 0;
};
class MocDeferredLinkMgr : public MocIDeferredLinkMgr {
public:
    MOCK_METHOD(void, PutDeferredLink, (const DeferredLinkInfo& info), (override));
    MOCK_METHOD(std::string, GetDeferredLink, (const std::string& bundleName, const std::vector<std::string>& domains),
        (override));
    MOCK_METHOD(void, RemoveDeferredLink, (const DeferredLinkInfo& info), (override));
};
void DoMocDeferredLinkMgr(std::shared_ptr<MocIDeferredLinkMgr> moc);
}
#endif  // APP_DOMAIN_VERIFY_MOCK_DEFERRED_LINK_MGR_H
