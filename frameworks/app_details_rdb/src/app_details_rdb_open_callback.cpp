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
#include "app_details_rdb_open_callback.h"
#include "app_details_rdb_data_define.h"
#include "app_domain_verify_hilog.h"
#include "rdb_errno.h"

namespace OHOS {
namespace AppDomainVerify {
AppDetailsRdbOpenCallback::AppDetailsRdbOpenCallback(const RdbConfigInfo& conf)
    : m_conf(conf)
{
}

int32_t AppDetailsRdbOpenCallback::OnCreate(NativeRdb::RdbStore& rdbStore)
{
    APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "RdbStore OnCreate");
    return NativeRdb::E_OK;
}
int32_t AppDetailsRdbOpenCallback::OnUpgrade(NativeRdb::RdbStore& rdbStore, int currentVersion, int targetVersion)
{
    APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE,
        "OnUpgrade currentVersion: %{public}d, targetVersion: %{public}d", currentVersion, targetVersion);
    return NativeRdb::E_OK;
}
int32_t AppDetailsRdbOpenCallback::OnDowngrade(
    NativeRdb::RdbStore& rdbStore, int currentVersion, int targetVersion)
{
    APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE,
        "OnDowngrade currentVersion: %{public}d, targetVersion: %{public}d", currentVersion, targetVersion);
    return NativeRdb::E_OK;
}
int32_t AppDetailsRdbOpenCallback::OnOpen(NativeRdb::RdbStore& rdbStore)
{
    APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "RdbStore OnOpen");
    return NativeRdb::E_OK;
}
int32_t AppDetailsRdbOpenCallback::onCorruption(std::string databaseFile)
{
    return NativeRdb::E_OK;
}
}  // namespace AppDomainVerify
}  // namespace OHOS
