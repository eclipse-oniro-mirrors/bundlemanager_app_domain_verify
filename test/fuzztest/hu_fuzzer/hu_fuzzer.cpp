/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "message_parcel.h"
#include "message_option.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include "sa_interface/app_domain_verify_mgr_service.h"
// 【融合点1】引入 v8.0 的新式武器
#include "want.h" 

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr uint32_t CODE_MAX = 16;
static AppDomainVerify::AppDomainVerifyMgrService appDomainVerifyMgrService;
const std::u16string INTERFACE_TOKEN = u"ohos.appDomainVerify.IAppDomainVerifyMgrService";

// 【融合点2】保留 v7.0 的稳定剂 (固定包名池)
// 这能确保持久化存储逻辑 (RDB) 稳定触发，不再靠运气
const std::vector<std::string> BUNDLE_POOL = {
    "com.ohos.test.app1",
    "com.ohos.test.app2",
    "com.ohos.settings",
    "com.example.demo"
};

std::string GetFuzzBundleName(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeBool()) {
        size_t index = fdp.ConsumeIntegralInRange<size_t>(0, BUNDLE_POOL.size() - 1);
        return BUNDLE_POOL[index];
    } else {
        std::string s = fdp.ConsumeRandomLengthString();
        // 确保非空，满足数据库 NOT NULL 约束
        return s.empty() ? "com.default.fallback" : s;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    while (fdp.remaining_bytes() > 0) {
        uint32_t code = fdp.ConsumeIntegralInRange<uint32_t>(0, CODE_MAX);
        
        MessageParcel dataParcel;
        dataParcel.WriteInterfaceToken(INTERFACE_TOKEN);

        switch (code) {
            // ==========================================
            // 第一类：查询类 (Code 0, 9, 10, 16)
            // ==========================================
            case 0: case 9: case 10: case 16:
                dataParcel.WriteString(GetFuzzBundleName(fdp));
                break;
            
            // ==========================================
            // 第二类：简单字符串 (Code 6, 13)
            // ==========================================
            case 6: case 13:
                dataParcel.WriteString(fdp.ConsumeRandomLengthString());
                break;

            // ==========================================
            // 【融合点3】核心插入 (Code 1) - v5-Lucky 的核心逻辑
            // ==========================================
            case 1: 
                {
                    dataParcel.WriteString(fdp.ConsumeRandomLengthString());
                    dataParcel.WriteString(GetFuzzBundleName(fdp));
                    dataParcel.WriteString(fdp.ConsumeRandomLengthString());
                    
                    // 这里保留了让你上次跑出 54% 覆盖率的关键循环结构
                    int32_t vectorSize = fdp.ConsumeIntegralInRange<int32_t>(1, 5);
                    dataParcel.WriteInt32(vectorSize);
                    for (int i = 0; i < vectorSize; ++i) {
                        // 强制 "https" 确保能通过 Filter，这也是上次成功的关键
                        dataParcel.WriteString("https"); 
                        
                        // 尽可能构造真实 Host
                        if (fdp.ConsumeBool()) {
                            dataParcel.WriteString("www.openharmony.cn"); 
                        } else {
                            dataParcel.WriteString(fdp.ConsumeRandomLengthString());
                        }

                        // 剩下的 5 个字段继续随机，保持 fuzz 的变异性
                        for(int j=0; j<5; ++j) dataParcel.WriteString(fdp.ConsumeRandomLengthString());
                    }
                }
                break;

            // ==========================================
            // 第四类：更新状态 (Code 5) - 激活 RDB Update
            // ==========================================
            case 5: 
                {
                    dataParcel.WriteString(GetFuzzBundleName(fdp));
                    if (fdp.remaining_bytes() > 0) {
                        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
                        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(len);
                        dataParcel.WriteBuffer(bytes.data(), bytes.size());
                    }
                }
                break;

            case 2:
                dataParcel.WriteString(fdp.ConsumeRandomLengthString());
                dataParcel.WriteString(GetFuzzBundleName(fdp));
                break;

            case 8:
                {
                    uint32_t vectorSize = fdp.ConsumeIntegralInRange<uint32_t>(0, 10);
                    dataParcel.WriteUint32(vectorSize);
                    for (uint32_t i = 0; i < vectorSize; ++i) {
                        dataParcel.WriteString("https://www.example.com");
                    }
                }
                break;

            // ==========================================
            // 【融合点4】v8.0 的新式武器：FilterAbilities (Code 3)
            // 目标：攻击 app_details_data_mgr.cpp (上次只有 8.9%)
            // ==========================================
            case 3: // FILTER_ABILITIES
                {
                    // 1. 构造一个合法的 Want 对象 (利用 v8 的优势)
                    AAFwk::Want want;
                    want.SetAction("ohos.want.action.viewData");
                    want.SetUri("https://www.openharmony.cn/test");
                    // 关键：WriteParcelable 可能会失败如果环境不对，所以我们加了 try-catch 或者依赖底层保护
                    // 但在 Fuzz 环境下，我们直接写进去
                    dataParcel.WriteParcelable(&want);

                    // 2. 构造 AbilityInfo 数组
                    int32_t abilitySize = fdp.ConsumeIntegralInRange<int32_t>(0, 5);
                    dataParcel.WriteInt32(abilitySize);
                    for (int i = 0; i < abilitySize; ++i) {
                        AbilityInfo info;
                        info.bundleName = GetFuzzBundleName(fdp); 
                        info.name = fdp.ConsumeRandomLengthString();
                        dataParcel.WriteParcelable(&info);
                    }
                }
                break;
            
            // Code 12 也是类似的逻辑，可以尝试攻击
            case 12: // QUERY_APP_DETAILS_WANT
                {
                    dataParcel.WriteString("https://www.openharmony.cn/test"); // url
                    // 需要 bundleName
                    dataParcel.WriteString(GetFuzzBundleName(fdp)); 
                }
                break;

            case 11:
                break;

            default:
                {
                    // 【融合点5】保留 v5 的随机乱打，防止漏掉未知接口
                    if (fdp.remaining_bytes() > 0) {
                        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
                        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(len);
                        dataParcel.WriteBuffer(bytes.data(), bytes.size());
                    }
                }
                break;
        }

        dataParcel.RewindRead(0);
        MessageParcel reply;
        MessageOption option;

        appDomainVerifyMgrService.OnRemoteRequest(code, dataParcel, reply, option);
    }

    return 0;
}
}