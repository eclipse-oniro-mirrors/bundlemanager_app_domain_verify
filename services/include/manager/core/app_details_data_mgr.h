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
#ifndef APP_DOMAIN_VERIFY_APP_DETAILS_DATA_MGR_H
#define APP_DOMAIN_VERIFY_APP_DETAILS_DATA_MGR_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include "cpp/mutex.h"
#include "want.h"
#include "lru_cache_util.h"
#include "filter_define.h"
#include "app_details_filter.h"
#include "app_details_rdb_data_manager.h"

namespace OHOS {
namespace AppDomainVerify {
enum AppDetailsCode {
    QUERY_SUCC,
    QUERY_FAIL
};

class AppDetailsDataMgr {
public:
    AppDetailsDataMgr();
    virtual ~AppDetailsDataMgr();
    int QueryAppDetailsWant(const std::string& url, AAFwk::Want& want, std::string& bundleName);
private:
    bool QueryAppDetailsWantByCache(const std::string& url, std::string& bundleName);
    bool QueryAppDetailsWantByRdb(const std::string& url, std::string& bundleName);
    void AddInfoToWant(AAFwk::Want& want, const std::string& bundleName);
    std::shared_ptr<LruCacheUtil<std::string, std::string>> lruCache_;
    std::shared_ptr<AppDetailsRdbDataMgr> rdbMgr_;
    std::shared_ptr<AppDetailsFilter> detailsFilter_;
    int64_t cacheBeginTime_ = 0;
    std::string agWantUrl_;
};
}  // namespace AppDomainVerify
}  // namespace OHOS
#endif  // APP_DETAILS_DATA_MGR_H