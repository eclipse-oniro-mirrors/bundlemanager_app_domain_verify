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

#ifndef APP_DOMAIN_VERIFY_MGR_SERVICE_STUB_H
#define APP_DOMAIN_VERIFY_MGR_SERVICE_STUB_H
#include <map>

#include "i_app_domain_verify_mgr_service.h"
#include "iremote_stub.h"
#include "event_handler.h"
#include "event_runner.h"
#include "message_parcel.h"

namespace OHOS {
namespace AppDomainVerify {
class AppDomainVerifyMgrServiceStub : public IRemoteStub<IAppDomainVerifyMgrService> {
public:
    API_EXPORT AppDomainVerifyMgrServiceStub();
    API_EXPORT ~AppDomainVerifyMgrServiceStub() override;
    API_EXPORT int32_t OnRemoteRequest(
        uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int32_t OnVerifyDomain(MessageParcel& data, MessageParcel& reply);
    int32_t OnClearDomainVerifyStatus(MessageParcel& data, MessageParcel& reply);
    int32_t OnFilterAbilities(MessageParcel& data, MessageParcel& reply);
    int32_t OnQueryDomainVerifyStatus(MessageParcel& data, MessageParcel& reply);
    int32_t OnQueryAllDomainVerifyStatus(MessageParcel& data, MessageParcel& reply);
    int32_t OnSaveDomainVerifyStatus(MessageParcel& data, MessageParcel& reply);
    int32_t OnIsAtomicServiceUrl(MessageParcel& data, MessageParcel& reply);
    int32_t OnConvertToExplicitWant(MessageParcel& data, MessageParcel& reply);
    int32_t OnUpdateWhiteListUrls(MessageParcel& data, MessageParcel& reply);
    int32_t OnQueryAssociatedDomains(MessageParcel& data, MessageParcel& reply);
    int32_t OnQueryAssociatedBundleNames(MessageParcel& data, MessageParcel& reply);
    int32_t OnGetDeferredLink(MessageParcel& data, MessageParcel& reply);
    int32_t OnQueryAppDetailsWant(MessageParcel& data, MessageParcel& reply);
    int32_t OnIsShortUrl(MessageParcel& data, MessageParcel& reply);
    int32_t OnConvertFromShortUrl(MessageParcel& data, MessageParcel& reply);
};
}  // namespace AppDomainVerify
}  // namespace OHOS

#endif  // APP_DOMAIN_VERIFY_MGR_SERVICE_STUB_H