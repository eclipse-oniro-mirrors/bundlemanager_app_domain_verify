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

#include "convertcallbackstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "convert_callback_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "convert_callback_interface_code.h"

using namespace OHOS::AppDomainVerify;

namespace OHOS {
    constexpr size_t THRESHOLD = 10;
    const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.appdomainverify.IConvertCallback";

    class ConvertCallbackStubFuzzer : public ConvertCallbackStub {
    public:
        ConvertCallbackStubFuzzer() = default;
        ~ConvertCallbackStubFuzzer() override = default;
        // Mock implementation
        void OnConvert(int resCode, TargetInfo& targetInfo) override {};
    };

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (size < THRESHOLD) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(data[0]);
        if (data[0] % 2 == 0) {
            code = static_cast<uint32_t>(ConvertCallbackInterfaceCode::ON_CONVERT_CALLBACK);
        }

        MessageParcel request;
        request.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);

        // Write the remaining data into Parcel to drive ReadInt32 and ReadParcelable
        request.WriteBuffer(data + 1, size - 1);
        request.RewindRead(0);

        MessageParcel reply;
        MessageOption option;

        ConvertCallbackStubFuzzer stub;
        stub.OnRemoteRequest(code, request, reply, option);

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

