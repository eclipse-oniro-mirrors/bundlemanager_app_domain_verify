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

#ifndef APP_DOMAIN_VERIFY_I_CONVERT_CALLBACK_PROXY_H
#define APP_DOMAIN_VERIFY_I_CONVERT_CALLBACK_PROXY_H
#include "iremote_proxy.h"
#include "i_convert_callback.h"

namespace OHOS {
namespace AppDomainVerify {
class ConvertCallbackProxy : public IRemoteProxy<IConvertCallback> {
public:
    explicit ConvertCallbackProxy(const sptr<IRemoteObject>& object);
    virtual ~ConvertCallbackProxy() override;

    virtual void OnConvert(int resCode, TargetInfo& targetInfo) override;

private:
    static inline BrokerDelegator<ConvertCallbackProxy> delegator_;
};
}
}
#endif  // APP_DOMAIN_VERIFY_I_CONVERT_CALLBACK_PROXY_H
