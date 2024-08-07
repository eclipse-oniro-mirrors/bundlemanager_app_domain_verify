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
#ifndef APP_DOMAIN_VERIFY_HISYSTEM_EVENT_H
#define APP_DOMAIN_VERIFY_HISYSTEM_EVENT_H
#include <string>
#include "hisysevent.h"

namespace OHOS {
namespace AppDomainVerify {
static constexpr char APP_DOMAIN_VERIFY[] = "APPDOMAINVERIFY";
namespace EventType {
const std::string APP_INSTALL_EVENT = "PKG_INSTALL";
const std::string APP_DELETE_EVENT = "PKG_UNINSTALL";
const std::string APP_VERIFY_EVENT = "PKG_VERIFY_RESULT";
}
namespace EventParamKey {
const std::string APP_ID = "APP_ID";
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string VERIFY_STATUS = "VERIFY_STATUS";
const std::string VERIFY_WAY = "VERIFY_WAY";
}
typedef enum EnumTaskType {
    IMMEDIATE_TASK,
    BOOT_REFRESH_TASK,
    SCHEDULE_REFRESH_TASK,
    UNKNOWN_TASK
} TaskType;

#define INSTALL_EVENT(appIdentifier, bundleName)                                                      \
    do {                                                                                              \
        HiSysEventWrite(APP_DOMAIN_VERIFY, EventType::APP_INSTALL_EVENT,                              \
            OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, EventParamKey::APP_ID, (appIdentifier), \
            EventParamKey::BUNDLE_NAME, (bundleName));                                                \
    } while (0)

#define UNINSTALL_EVENT(appIdentifier, bundleName)                                                    \
    do {                                                                                              \
        HiSysEventWrite(APP_DOMAIN_VERIFY, EventType::APP_DELETE_EVENT,                               \
            OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, EventParamKey::APP_ID, (appIdentifier), \
            EventParamKey::BUNDLE_NAME, (bundleName));                                                \
    } while (0)

#define VERIFY_RESULT_EVENT(appIdentifier, bundleName, type, status)                                                   \
    do {                                                                                                               \
        HiSysEventWrite(APP_DOMAIN_VERIFY, EventType::APP_VERIFY_EVENT,                                                \
            OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, EventParamKey::APP_ID, (appIdentifier),                  \
            EventParamKey::BUNDLE_NAME, (bundleName), EventParamKey::VERIFY_WAY, (type), EventParamKey::VERIFY_STATUS, \
            (status));                                                                                                 \
    } while (0)
}
}
#endif