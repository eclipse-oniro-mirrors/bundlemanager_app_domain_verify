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

#include <memory>
#include "app_domain_verify_mgr_service_stub.h"
#include "sa_interface/app_domain_verify_mgr_interface_code.h"
#include "errors.h"
#include "app_domain_verify_parcel_util.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "want.h"

namespace OHOS {
namespace AppDomainVerify {
namespace {
const std::string TASK_ID = "unload";
}
AppDomainVerifyMgrServiceStub::AppDomainVerifyMgrServiceStub()
{
}
AppDomainVerifyMgrServiceStub::~AppDomainVerifyMgrServiceStub()
{
}
int32_t AppDomainVerifyMgrServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "onRemoteRequest##code = %{public}u", code);
    std::u16string myDescripter = AppDomainVerifyMgrServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "end##descriptor checked fail");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    switch (code) {
        case static_cast<uint32_t>(static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::QUERY_VERIFY_STATUS)):
            return OnQueryDomainVerifyStatus(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::VERIFY_DOMAIN):
            return OnVerifyDomain(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::CLEAR_DOMAIN_VERIFY_RESULT):
            return OnClearDomainVerifyStatus(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::FILTER_ABILITIES):
            return OnFilterAbilities(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::QUERY_ALL_VERIFY_STATUS):
            return OnQueryAllDomainVerifyStatus(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::SAVE_VERIFY_STATUS):
            return OnSaveDomainVerifyStatus(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::IS_ATOMIC_SERVICE_URL):
            return OnIsAtomicServiceUrl(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::CONVERT_TO_EXPLICIT_WANT):
            return OnConvertToExplicitWant(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::UPDATE_WHITE_LIST_URLS):
            return OnUpdateWhiteListUrls(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::QUERY_ASSOCIATED_DOMAINS):
            return OnQueryAssociatedDomains(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::QUERY_ASSOCIATED_BUNDLE_NAMES):
            return OnQueryAssociatedBundleNames(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::GET_DEFERRED_LINK):
            return OnGetDeferredLink(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::QUERY_APP_DETAILS_WANT):
            return OnQueryAppDetailsWant(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::IS_SHORT_URL):
            return OnIsShortUrl(data, reply);
        case static_cast<uint32_t>(AppDomainVerifyMgrInterfaceCode::CONVERT_FROM_SHORT_URL):
            return OnConvertFromShortUrl(data, reply);
        default:
            APP_DOMAIN_VERIFY_HILOGW(
                APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "receive unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t AppDomainVerifyMgrServiceStub::OnVerifyDomain(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string appIdentifier = data.ReadString();
    std::string bundleName = data.ReadString();
    std::string fingerprint = data.ReadString();
    int32_t size = data.ReadInt32();
    if (IsInvalidParcelArraySize(size)) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable size invalid.");
        return false;
    }
    std::vector<SkillUri> skillUris;
    for (int32_t i = 0; i < size; i++) {
        std::unique_ptr<SkillUri> info(data.ReadParcelable<SkillUri>());
        if (!info) {
            APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable skillUri failed.");
            return ERR_INVALID_VALUE;
        }
        skillUris.emplace_back(*info);
    }

    VerifyDomain(appIdentifier, bundleName, fingerprint, skillUris);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}

int32_t AppDomainVerifyMgrServiceStub::OnClearDomainVerifyStatus(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string appIdentifier = data.ReadString();
    std::string bundleName = data.ReadString();
    bool status = ClearDomainVerifyStatus(appIdentifier, bundleName);

    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Bool, reply, status);
    return ERR_OK;
}

int32_t AppDomainVerifyMgrServiceStub::OnFilterAbilities(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::unique_ptr<OHOS::AAFwk::Want> w(data.ReadParcelable<OHOS::AAFwk::Want>());
    OHOS::AAFwk::Want want;
    if (!w) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable want failed.");
        return ERR_INVALID_VALUE;
    }
    want = *w;
    std::vector<OHOS::AppExecFwk::AbilityInfo> originAbilityInfos;
    int32_t size = data.ReadInt32();
    if (IsInvalidParcelArraySize(size)) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable size invalid.");
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
        std::unique_ptr<OHOS::AppExecFwk::AbilityInfo> info(data.ReadParcelable<OHOS::AppExecFwk::AbilityInfo>());
        if (!info) {
            APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable abilityInfo failed.");
            return ERR_INVALID_VALUE;
        }
        originAbilityInfos.emplace_back(*info);
    }
    std::vector<OHOS::AppExecFwk::AbilityInfo> filtedAbilityInfos;
    bool status = FilterAbilities(want, originAbilityInfos, filtedAbilityInfos);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Bool, reply, status);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Int32, reply, filtedAbilityInfos.size());
    for (auto& it : filtedAbilityInfos) {
        WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Parcelable, reply, &it);
    }
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}

int32_t AppDomainVerifyMgrServiceStub::OnQueryDomainVerifyStatus(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string bundleName = data.ReadString();
    DomainVerifyStatus domainVerificationState;
    bool status = QueryDomainVerifyStatus(bundleName, domainVerificationState);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Bool, reply, status);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Int32, reply, domainVerificationState);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}

int32_t AppDomainVerifyMgrServiceStub::OnQueryAllDomainVerifyStatus(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    BundleVerifyStatusInfo bundleVerifyStatusInfo;
    bool status = QueryAllDomainVerifyStatus(bundleVerifyStatusInfo);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Bool, reply, status);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Parcelable, reply, &bundleVerifyStatusInfo);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}

int32_t AppDomainVerifyMgrServiceStub::OnSaveDomainVerifyStatus(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string bundleName = data.ReadString();
    std::unique_ptr<VerifyResultInfo> verifyResultInfo(data.ReadParcelable<VerifyResultInfo>());
    if (verifyResultInfo == nullptr) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "verifyResultInfo null");
        return ERR_INVALID_VALUE;
    }
    bool status = SaveDomainVerifyStatus(bundleName, *verifyResultInfo);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Bool, reply, status);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}
int32_t AppDomainVerifyMgrServiceStub::OnIsAtomicServiceUrl(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string url = data.ReadString();
    bool status = IsAtomicServiceUrl(url);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Bool, reply, status);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}
int32_t AppDomainVerifyMgrServiceStub::OnUpdateWhiteListUrls(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    uint32_t size = data.ReadUint32();
    if (IsInvalidParcelArraySize(size)) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable size invalid.");
        return false;
    }
    std::vector<std::string> urls;
    for (uint32_t i = 0; i < size; i++) {
        auto url = data.ReadString();
        urls.emplace_back(url);
    }
    UpdateWhiteListUrls(urls);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return 0;
}
int32_t AppDomainVerifyMgrServiceStub::OnConvertToExplicitWant(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    OHOS::AAFwk::Want want;
    std::unique_ptr<OHOS::AAFwk::Want> w(data.ReadParcelable<OHOS::AAFwk::Want>());
    if (!w) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable want failed.");
        return ERR_INVALID_VALUE;
    }
    want = *w;
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read failed");
        return ERR_INVALID_VALUE;
    }
    sptr<IConvertCallback> cleanCacheCallback = iface_cast<IConvertCallback>(object);
    ConvertToExplicitWant(want, cleanCacheCallback);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}
int32_t AppDomainVerifyMgrServiceStub::OnQueryAssociatedDomains(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string bundleName;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, bundleName);

    std::vector<std::string> domains;
    int ret = QueryAssociatedDomains(bundleName, domains);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ret);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, domains.size());
    for (const auto& i : domains) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, reply, i);
    }
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}
int32_t AppDomainVerifyMgrServiceStub::OnQueryAssociatedBundleNames(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string domain;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, domain);
    std::vector<std::string> bundleNames;

    int ret = QueryAssociatedBundleNames(domain, bundleNames);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ret);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, bundleNames.size());
    for (const auto& i : bundleNames) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, reply, i);
    }
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}
int32_t AppDomainVerifyMgrServiceStub::OnGetDeferredLink(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string link;
    int ret = GetDeferredLink(link);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, reply, ret);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, reply, link);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}

int32_t AppDomainVerifyMgrServiceStub::OnQueryAppDetailsWant(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    AAFwk::Want want;
    std::string url;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, url);
    std::unique_ptr<OHOS::AAFwk::Want> w(data.ReadParcelable<OHOS::AAFwk::Want>());
    if (!w) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable want failed.");
        return ERR_INVALID_VALUE;
    }
    want = *w;
    int ret = QueryAppDetailsWant(url, want);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Int32, reply, ret);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Parcelable, reply, &want);
    return ERR_OK;
}
int32_t AppDomainVerifyMgrServiceStub::OnIsShortUrl(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    std::string url = data.ReadString();
    bool status = IsAtomicServiceUrl(url);
    WRITE_PARCEL_AND_RETURN_INT_IF_FAIL(Bool, reply, status);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}
int32_t AppDomainVerifyMgrServiceStub::OnConvertFromShortUrl(MessageParcel& data, MessageParcel& reply)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "called");
    OHOS::AAFwk::Want want;
    std::unique_ptr<OHOS::AAFwk::Want> w(data.ReadParcelable<OHOS::AAFwk::Want>());
    if (!w) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read parcelable want failed.");
        return ERR_INVALID_VALUE;
    }
    want = *w;
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "read failed");
        return ERR_INVALID_VALUE;
    }
    sptr<IConvertCallback> cleanCacheCallback = iface_cast<IConvertCallback>(object);
    ConvertToExplicitWant(want, cleanCacheCallback);
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call end");
    return ERR_OK;
}

}  // namespace AppDomainVerify
}  // namespace OHOS