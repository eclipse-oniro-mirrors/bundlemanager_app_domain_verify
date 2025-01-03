/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef APP_DOMAIN_VERIFY_SERVICE_INCLUDE_RDB_DATA_DEFINE_H
#define APP_DOMAIN_VERIFY_SERVICE_INCLUDE_RDB_DATA_DEFINE_H
#include <filesystem>
#include <string>
#include "app_details_base_item.h"
#include "app_details_meta_item.h"
#include "app_details_rdb_item.h"

namespace OHOS {
namespace AppDomainVerify {
using TransCallback = std::function<bool()>;
const static std::string PATH = "path";
const static std::string PATH_START_WITH = "pathStartWith";
const static std::string PATH_REGEX = "pathRegex";

struct RdbConfigInfo {
    std::string rdbPath;
    std::string rdbName;
    int version = 0;
    bool fileCreated = true;
};
}
}

#endif  // APP_DOMAIN_VERIFY_SERVICE_INCLUDE_RDB_DATA_MANAGER_H