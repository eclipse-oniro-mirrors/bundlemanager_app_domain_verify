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
#include "app_domain_verify_agent_service_proxy.h"
#include "agent_interface_code.h"
#include "system_ability_definition.h"
#include "app_domain_verify_parcel_util.h"

namespace OHOS {
namespace AppDomainVerify {
AppDomainVerifyAgentServiceProxy::AppDomainVerifyAgentServiceProxy(const sptr<IRemoteObject>& object)
    : IRemoteProxy<IAppDomainVerifyAgentService>(object)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_AGENT_MODULE_SERVICE, "new instance created.");
}
AppDomainVerifyAgentServiceProxy::~AppDomainVerifyAgentServiceProxy()
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_AGENT_MODULE_SERVICE, "instance dead.");
}

void AppDomainVerifyAgentServiceProxy::SingleVerify(
    const AppVerifyBaseInfo& appVerifyBaseInfo, const VerifyResultInfo &verifyResultInfo)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_AGENT_MODULE_SERVICE, "called");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WRITE_PARCEL_AND_RETURN_IF_FAIL(InterfaceToken, data, GetDescriptor());
    WRITE_PARCEL_AND_RETURN_IF_FAIL(Parcelable, data, &appVerifyBaseInfo);
    WRITE_PARCEL_AND_RETURN_IF_FAIL(Parcelable, data, &verifyResultInfo);
    int32_t error = Remote()->SendRequest(AgentInterfaceCode::SINGLE_VERIFY, data, reply, option);
    if (error != ERR_NONE) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_AGENT_MODULE_SERVICE, "SingleVerify failed, error: %d", error);
    }
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_AGENT_MODULE_SERVICE, "call end");
}
void AppDomainVerifyAgentServiceProxy::ConvertToExplicitWant(
    OHOS::AAFwk::Want& implicitWant, sptr<IConvertCallback>& callback)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_CLIENT, "called");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    WRITE_PARCEL_AND_RETURN_IF_FAIL(InterfaceToken, data, GetDescriptor());
    WRITE_PARCEL_AND_RETURN_IF_FAIL(Parcelable, data, &implicitWant);
    WRITE_PARCEL_AND_RETURN_IF_FAIL(RemoteObject, data, callback->AsObject());

    int32_t error = Remote()->SendRequest(AgentInterfaceCode::CONVERT_TO_EXPLICIT_WANT, data, reply, option);
    if (error != ERR_NONE) {
        APP_DOMAIN_VERIFY_HILOGE(
            APP_DOMAIN_VERIFY_MGR_MODULE_CLIENT, "ConvertToExplicitWant failed, error: %d", error);
    }
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_CLIENT, "call end");
}
}  // namespace AppDomainVerify
}  // namespace OHOS
