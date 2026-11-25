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

#include "r_appdomain_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "domain_json_util.h"
#include "domain_verifier.h"
#include "domain_url_util.h"
#include "app_verify_base_info.h"
#include "asset_json_obj.h"
#include "http_client.h"

#define BYTE_OFFSET_0 0
#define BYTE_OFFSET_1 1
#define MIN_SIZE_FOR_SELECTOR 1
#define NUM_FUZZ_TARGETS 3
#define NUM_RESPONSE_CODES 5
#define INDEX_FUZZ_JSON 0
#define INDEX_FUZZ_URL 1
#define INDEX_FUZZ_VERIFY 2

namespace OHOS {
namespace AppDomainVerify {

using NetResponseCode = OHOS::NetStack::HttpClient::ResponseCode;

static const NetResponseCode kResponseCodes[NUM_RESPONSE_CODES] = {
    NetResponseCode::OK,
    NetResponseCode::MULT_CHOICE,
    NetResponseCode::BAD_REQUEST,
    NetResponseCode::INTERNAL_ERROR,
    NetResponseCode::PARTIAL,
};

static void FuzzJsonUtil(const std::string& payload)
{
    AssetJsonObj assetJsonObj;
    (void)JsonUtil::Parse(payload, assetJsonObj);
}

static void FuzzUrlUtil(const std::string& payload)
{
    (void)UrlUtil::IsValidUrl(payload);
    (void)UrlUtil::GetHost(payload);
    (void)UrlUtil::GetScheme(payload);
    (void)UrlUtil::IsValidAppDomainVerifyHost(payload);
}

static void FuzzVerifyHost(uint8_t selector, const std::string& payload)
{
    size_t idx = static_cast<size_t>(selector % NUM_RESPONSE_CODES);
    NetResponseCode code = kResponseCodes[idx];
    AppVerifyBaseInfo appVerifyBaseInfo;
    (void)DomainVerifier::VerifyHost(code, payload, appVerifyBaseInfo);
}

}  // namespace AppDomainVerify
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < MIN_SIZE_FOR_SELECTOR) {
        OHOS::AppDomainVerify::AssetJsonObj emptyObj;
        (void)OHOS::AppDomainVerify::JsonUtil::Parse("", emptyObj);
        return 0;
    }

    uint8_t selector = data[BYTE_OFFSET_0];
    std::string payload(
        reinterpret_cast<const char*>(data + BYTE_OFFSET_1),
        size - MIN_SIZE_FOR_SELECTOR);

    size_t idx = static_cast<size_t>(selector % NUM_FUZZ_TARGETS);
    if (idx == INDEX_FUZZ_JSON) {
        OHOS::AppDomainVerify::FuzzJsonUtil(payload);
    } else if (idx == INDEX_FUZZ_URL) {
        OHOS::AppDomainVerify::FuzzUrlUtil(payload);
    } else {
        OHOS::AppDomainVerify::FuzzVerifyHost(selector, payload);
    }

    return 0;
}
