/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef MOCK_BUNDLE_MANAGER_H
#define MOCK_BUNDLE_MANAGER_H

#include <vector>
#include <gmock/gmock.h>
#include "bundlemgr/bundle_mgr_interface.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {

class BundleMgrProxy : public IRemoteProxy<IBundleMgr> {
public:
    explicit BundleMgrProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IBundleMgr>(impl)
    {
    }
    virtual ~BundleMgrProxy()
    {
    }
    ErrCode GetBundleInfoV9(
        const std::string& bundleName, int32_t flags, BundleInfo& bundleInfo, int32_t userId) override;
    bool GetBundleInfo(const std::string& bundleName, const BundleFlag flag, BundleInfo& bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    bool GetBundleInfo(const std::string& bundleName, int32_t flags, BundleInfo& bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    bool GetBundleNameForUid(const int uid, std::string& bundleName) override;
};

class BundleMgrStub : public IRemoteStub<IBundleMgr> {
public:
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
};

class MocBundleMgrService : public BundleMgrStub {
public:
    MocBundleMgrService(){};
    ~MocBundleMgrService(){};

    MOCK_METHOD(ErrCode, GetBundleInfoV9,
        (const std::string& bundleName, int32_t flags, BundleInfo& bundleInfo, int32_t userId), (override));
    MOCK_METHOD(bool, GetBundleInfo,
        (const std::string& bundleName, const BundleFlag flag, BundleInfo& bundleInfo, int32_t userId), (override));
    MOCK_METHOD(bool, GetBundleInfo,
        (const std::string& bundleName, int32_t flags, BundleInfo& bundleInfo, int32_t userId), (override));
    MOCK_METHOD(bool, GetBundleNameForUid, (const int uid, std::string& bundleName), (override));
};

class BundleMgrService : public BundleMgrStub {
public:
    BundleMgrService(){};
    ~BundleMgrService(){};

    ErrCode GetBundleInfoV9(
        const std::string& bundleName, int32_t flags, BundleInfo& bundleInfo, int32_t userId) override;
    bool GetBundleInfo(const std::string& bundleName, const BundleFlag flag, BundleInfo& bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    bool GetBundleInfo(const std::string& bundleName, int32_t flags, BundleInfo& bundleInfo,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    bool GetBundleNameForUid(const int uid, std::string& bundleName) override;
    std::shared_ptr<MocBundleMgrService> impl = nullptr;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_BUNDLE_MANAGER_H
