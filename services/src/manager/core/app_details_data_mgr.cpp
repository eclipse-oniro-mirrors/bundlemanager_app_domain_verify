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

#include <memory>
#include <new>
#include <cstdint>
#include "skill.h"
#include "want.h"
#include "app_details_filter.h"
#include "app_details_meta_item.h"
#include "app_details_rdb_data_define.h"
#include "app_details_rdb_const_define.h"
#include "app_details_rdb_data_manager.h"
#include "app_domain_verify_error.h"
#include "domain_url_util.h"
#include "app_domain_verify_hilog.h"
#include "filter_define.h"
#include "lru_cache_util.h"
#include "app_details_data_mgr.h"


namespace OHOS {
namespace AppDomainVerify {
const static std::string OHOS_WANT_ACTION_APPDETAILS = "ohos.want.action.appdetail";
const static int64_t CACHE_TIME_S = 300;
const static int MAX_CACHE_CNT = 10;
AppDetailsDataMgr::AppDetailsDataMgr()
{
    lruCache_ = std::make_shared<LruCacheUtil<std::string, std::string>>(MAX_CACHE_CNT);
    rdbMgr_ = std::make_shared<AppDetailsRdbDataMgr>(false);
};

AppDetailsDataMgr::~AppDetailsDataMgr()
{};

int AppDetailsDataMgr::QueryAppDetailsWant(const std::string &url, AAFwk::Want& want, std::string& bundleName)
{
    APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "call, url:%{private}s", url.c_str());
    std::string bundleNameQuery;
    do {
        if (QueryAppDetailsWantByCache(url, bundleNameQuery)) {
            APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "query success from cache");
            break;
        }
        if (QueryAppDetailsWantByRdb(url, bundleNameQuery)) {
            APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "query success from rdb");
            break;
        }
        APP_DOMAIN_VERIFY_HILOGI(APP_DOMAIN_VERIFY_MGR_MODULE_SERVICE, "query fail.");
        return QUERY_FAIL;
    } while (false);
    AddInfoToWant(want, bundleNameQuery);
    bundleName = bundleNameQuery;
    return QUERY_SUCC;
};

bool AppDetailsDataMgr::QueryAppDetailsWantByCache(const std::string& url, std::string& bundleName)
{
    int64_t currTime = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now())
                          .time_since_epoch()
                          .count();
    if (currTime - cacheBeginTime_ > CACHE_TIME_S) {
        cacheBeginTime_ = currTime;
        lruCache_->Clear();
        return false;
    }
    std::string value;
    if (lruCache_->Get(url, value)) {
        bundleName = value;
        return true;
    }
    return false;
};

bool AppDetailsDataMgr::QueryAppDetailsWantByRdb(const std::string& url, std::string& bundleName)
{
    std::vector<AppDetailsRdbItem> rdbDetails;
    std::string domain = UrlUtil::GetHost(url);
    if (!rdbMgr_->QueryDataByDomain(APP_DETAILS_TABLE, domain, rdbDetails)) {
        APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "query fail.");
        return false;
    }
    std::vector<AppDetailInfo> appDetails;
    std::vector<AppDetailInfo> appDetailsRet;
    for (auto& detail : rdbDetails) {
        AppDetailInfo info;
        info.bundleName = detail.bundleName;
        info.skillUri.host = detail.domain;
        info.skillUri.scheme = detail.scheme;
        if (detail.pathType == PATH) {
            info.skillUri.path = detail.path;
        }
        if (detail.pathType == PATH_START_WITH) {
            info.skillUri.pathStartWith = detail.path;
        }
        if (detail.pathType == PATH_REGEX) {
            info.skillUri.pathRegex = detail.path;
        }
        appDetails.emplace_back(info);
    }
    if (!detailsFilter_->Filter(appDetails, appDetailsRet, url)) {
        return false;
    }
    bundleName = appDetailsRet.front().bundleName;
    lruCache_->Put(url, appDetailsRet.front().bundleName);
    return true;
};

void AppDetailsDataMgr::AddInfoToWant(AAFwk::Want& want, const std::string& bundleName)
{
    MetaItem info;
    if (agWantUrl_.empty()) {
        rdbMgr_->QueryMetaData(APP_DETAILS_TABLE, info);
        agWantUrl_ = info.tableExtInfo;
    }
    want.SetAction(OHOS_WANT_ACTION_APPDETAILS);
    want.SetUri(agWantUrl_ + bundleName);
    return;
};

}
}