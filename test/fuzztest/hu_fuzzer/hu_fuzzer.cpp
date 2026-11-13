/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "message_parcel.h"
#include "message_option.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include "sa_interface/app_domain_verify_mgr_service.h"
#include "want.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr uint32_t CODE_MAX = 16;
constexpr int32_t VECTOR_SIZE_MIN = 1;
constexpr int32_t VECTOR_SIZE_MAX = 5;
constexpr int32_t LOOP_COUNT_MAX = 10;
constexpr int32_t RANDOM_STRING_LOOP = 5;

constexpr uint32_t CMD_VERIFY_DOMAIN = 1;
constexpr uint32_t CMD_FILTER_ABILITIES = 3;
constexpr uint32_t CMD_SAVE_VERIFY_STATUS = 5;
constexpr uint32_t CMD_QUERY_DETAILS_WANT = 12;
constexpr uint32_t CMD_CODE_0 = 0;
constexpr uint32_t CMD_CODE_2 = 2;
constexpr uint32_t CMD_CODE_6 = 6;
constexpr uint32_t CMD_CODE_8 = 8;
constexpr uint32_t CMD_CODE_9 = 9;
constexpr uint32_t CMD_CODE_10 = 10;
constexpr uint32_t CMD_CODE_11 = 11;
constexpr uint32_t CMD_CODE_13 = 13;
constexpr uint32_t CMD_CODE_16 = 16;

static AppDomainVerify::AppDomainVerifyMgrService appDomainVerifyMgrService;
const std::u16string INTERFACE_TOKEN = u"ohos.appDomainVerify.IAppDomainVerifyMgrService";

const std::vector<std::string> BUNDLE_POOL = {
    "com.ohos.test.app1",
    "com.ohos.test.app2",
    "com.ohos.settings",
    "com.example.demo"
};

std::string GetFuzzBundleName(FuzzedDataProvider &fdp)
{
    if (fdp.ConsumeBool()) {
        size_t index = fdp.ConsumeIntegralInRange<size_t>(0, BUNDLE_POOL.size() - 1);
        return BUNDLE_POOL[index];
    } else {
        std::string s = fdp.ConsumeRandomLengthString();
        return s.empty() ? "com.default.fallback" : s;
    }
}

void FuzzVerifyDomain(FuzzedDataProvider &fdp, MessageParcel &dataParcel)
{
    dataParcel.WriteString(fdp.ConsumeRandomLengthString());
    dataParcel.WriteString(GetFuzzBundleName(fdp));
    dataParcel.WriteString(fdp.ConsumeRandomLengthString());

    int32_t vectorSize = fdp.ConsumeIntegralInRange<int32_t>(VECTOR_SIZE_MIN, VECTOR_SIZE_MAX);
    dataParcel.WriteInt32(vectorSize);
    for (int i = 0; i < vectorSize; ++i) {
        dataParcel.WriteString("https");
        if (fdp.ConsumeBool()) {
            dataParcel.WriteString("www.openharmony.cn");
        } else {
            dataParcel.WriteString(fdp.ConsumeRandomLengthString());
        }
        for (int j = 0; j < RANDOM_STRING_LOOP; ++j) {
            dataParcel.WriteString(fdp.ConsumeRandomLengthString());
        }
    }
}

void FuzzFilterAbilities(FuzzedDataProvider &fdp, MessageParcel &dataParcel)
{
    AAFwk::Want want;
    want.SetAction("ohos.want.action.viewData");
    want.SetUri("https://www.openharmony.cn/test");
    dataParcel.WriteParcelable(&want);

    int32_t abilitySize = fdp.ConsumeIntegralInRange<int32_t>(0, VECTOR_SIZE_MAX);
    dataParcel.WriteInt32(abilitySize);
    for (int i = 0; i < abilitySize; ++i) {
        AbilityInfo info;
        info.bundleName = GetFuzzBundleName(fdp);
        info.name = fdp.ConsumeRandomLengthString();
        dataParcel.WriteParcelable(&info);
    }
}

void FuzzSaveVerifyStatus(FuzzedDataProvider &fdp, MessageParcel &dataParcel)
{
    dataParcel.WriteString(GetFuzzBundleName(fdp));
    if (fdp.remaining_bytes() > 0) {
        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(len);
        dataParcel.WriteBuffer(bytes.data(), bytes.size());
    }
}

void FuzzDefault(FuzzedDataProvider &fdp, MessageParcel &dataParcel)
{
    if (fdp.remaining_bytes() > 0) {
        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(len);
        dataParcel.WriteBuffer(bytes.data(), bytes.size());
    }
}

void FuzzCode8(FuzzedDataProvider &fdp, MessageParcel &dataParcel)
{
    uint32_t vectorSize = fdp.ConsumeIntegralInRange<uint32_t>(0, LOOP_COUNT_MAX);
    dataParcel.WriteUint32(vectorSize);
    for (uint32_t i = 0; i < vectorSize; ++i) {
        dataParcel.WriteString("https://www.example.com");
    }
}

void DispatchFuzzTest(uint32_t code, FuzzedDataProvider &fdp, MessageParcel &dataParcel)
{
    switch (code) {
        case CMD_CODE_0:
        case CMD_CODE_9:
        case CMD_CODE_10:
        case CMD_CODE_16:
            dataParcel.WriteString(GetFuzzBundleName(fdp));
            break;
        case CMD_CODE_6:
        case CMD_CODE_13:
            dataParcel.WriteString(fdp.ConsumeRandomLengthString());
            break;
        case CMD_VERIFY_DOMAIN:
            FuzzVerifyDomain(fdp, dataParcel);
            break;
        case CMD_SAVE_VERIFY_STATUS:
            FuzzSaveVerifyStatus(fdp, dataParcel);
            break;
        case CMD_CODE_2:
            dataParcel.WriteString(fdp.ConsumeRandomLengthString());
            dataParcel.WriteString(GetFuzzBundleName(fdp));
            break;
        case CMD_CODE_8:
            FuzzCode8(fdp, dataParcel);
            break;
        case CMD_FILTER_ABILITIES:
            FuzzFilterAbilities(fdp, dataParcel);
            break;
        case CMD_QUERY_DETAILS_WANT:
            dataParcel.WriteString("https://www.openharmony.cn/test");
            dataParcel.WriteString(GetFuzzBundleName(fdp));
            break;
        case CMD_CODE_11:
            break;
        default:
            FuzzDefault(fdp, dataParcel);
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    while (fdp.remaining_bytes() > 0) {
        uint32_t code = fdp.ConsumeIntegralInRange<uint32_t>(0, CODE_MAX);
        
        MessageParcel dataParcel;
        dataParcel.WriteInterfaceToken(INTERFACE_TOKEN);

        DispatchFuzzTest(code, fdp, dataParcel);

        dataParcel.RewindRead(0);
        MessageParcel reply;
        MessageOption option;

        appDomainVerifyMgrService.OnRemoteRequest(code, dataParcel, reply, option);
    }
    return 0;
}
}