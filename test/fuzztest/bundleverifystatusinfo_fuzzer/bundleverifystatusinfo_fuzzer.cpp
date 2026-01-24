/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bundleverifystatusinfo_fuzzer.h"
#include "bundle_verify_status_info.h"
#include <parcel.h>
#include <securec.h>
#include <random>

using namespace OHOS::AppDomainVerify;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (size == 0) {
            return false;
        }

        // Fuzz VerifyResultInfo Unmarshalling
        Parcel parcel;
        parcel.WriteBuffer(data, size);
        VerifyResultInfo* resultInfo = VerifyResultInfo::Unmarshalling(parcel);
        if (resultInfo != nullptr) {
            Parcel outParcel;
            resultInfo->Marshalling(outParcel);
            resultInfo->Dump();
            delete resultInfo;
        }

        // Fuzz VerifyResultInfo fields
        VerifyResultInfo info;
        std::string str(reinterpret_cast<const char*>(data), size);
        info.appIdentifier = str;
        VerifyStatus status;
        status.status = InnerVerifyStatus::UNKNOWN;
        status.retryCnt = static_cast<int>(size % 100);
        status.verifyTime = str;
        status.priority = static_cast<int>(size % 100);
        info.hostVerifyStatusMap.insert({str, status});
        Parcel outParcel2;
        info.Marshalling(outParcel2);

        // Fuzz BundleVerifyStatusInfo Unmarshalling
        Parcel parcel2;
        parcel2.WriteBuffer(data, size);
        BundleVerifyStatusInfo* bundleInfo = BundleVerifyStatusInfo::Unmarshalling(parcel2);
        if (bundleInfo != nullptr) {
            Parcel outParcel3;
            bundleInfo->Marshalling(outParcel3);
            delete bundleInfo;
        }

        // Fuzz BundleVerifyStatusInfo fields
        BundleVerifyStatusInfo bInfo;
        bInfo.bundleVerifyStatusInfoMap_.insert({str, info});
        Parcel outParcel4;
        bInfo.Marshalling(outParcel4);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

