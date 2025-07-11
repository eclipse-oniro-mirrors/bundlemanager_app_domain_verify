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
#ifndef APP_DOMAIN_VERIFY_WHITELISTCONFIGMANAGER_H
#define APP_DOMAIN_VERIFY_WHITELISTCONFIGMANAGER_H
#include <string>
#include <unordered_set>
#include <vector>
#include <atomic>
#include "singleton.h"
#include "preferences.h"
#include "preferences_helper.h"
namespace OHOS::AppDomainVerify {
class WhiteListConfigMgr {
public:
    explicit WhiteListConfigMgr();
    virtual ~WhiteListConfigMgr();
    bool IsInWhiteList(const std::string& url);
    void UpdateWhiteList(const std::unordered_set<std::string>& whiteList);
protected:
    static bool IsMatched(const std::string& url, const std::string& regPatten);
    void Load();
    void LoadDefault();
    void LoadDynamic();
    bool Save();
    void Split(std::string urlList);
    std::shared_ptr<NativePreferences::Preferences> GetPreference(const std::string& path);
    std::string defaultWhiteUrl_;
    std::unordered_set<std::string> whiteListSet_;
    std::shared_ptr<NativePreferences::Preferences> preferences_;
    std::mutex whiteListLock_;
};

}

#endif  // APP_DOMAIN_VERIFY_WHITELISTCONFIGMANAGER_H
