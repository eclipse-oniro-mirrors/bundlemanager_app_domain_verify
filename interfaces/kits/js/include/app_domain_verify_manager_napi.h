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

#ifndef APP_DOMAIN_VERIFY_MANAGER_NAPI_H
#define APP_DOMAIN_VERIFY_MANAGER_NAPI_H
#include "napi/native_api.h"
#include "napi/native_node_api.h"
namespace OHOS::AppDomainVerify {
napi_value QueryAssociatedDomains(napi_env env, napi_callback_info info);
napi_value QueryAssociatedBundleNames(napi_env env, napi_callback_info info);
}
#endif  // APP_DOMAIN_VERIFY_MANAGER_NAPI_H
