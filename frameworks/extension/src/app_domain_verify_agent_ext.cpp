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

#include "app_domain_verify_agent_ext.h"
#include "app_domain_verify_error.h"

namespace OHOS {
namespace AppDomainVerify {
ErrorCode AppDomainVerifyAgentExt::CompleteVerifyRefresh(
    const BundleVerifyStatusInfo& bundleVerifyStatusInfo, TaskType type)
{
    return ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND;
}
ErrorCode AppDomainVerifyAgentExt::SingleVerify(
    const AppVerifyBaseInfo& appVerifyBaseInfo, const VerifyResultInfo& verifyResultInfo)
{
    return ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND;
}
ErrorCode AppDomainVerifyAgentExt::ConvertToExplicitWant(AAFwk::Want& implicitWant, sptr<IConvertCallback>& callback)
{
    return ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND;
}
ErrorCode AppDomainVerifyAgentExt::UpdateWhiteList()
{
    return ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND;
}
ErrorCode AppDomainVerifyAgentExt::UpdateAppDetails()
{
    return ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND;
}
ErrorCode AppDomainVerifyAgentExt::CommonTransact(uint32_t opcode, const std::string& request, std::string& response)
{
    return ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND;
}
}
}