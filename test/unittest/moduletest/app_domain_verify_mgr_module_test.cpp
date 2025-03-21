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

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include "mock_verify_agent.h"
#include "app_domain_verify_agent_service_proxy.h"
#include "refbase.h"
#include "mock_constant.h"
#include "mock_verify_mgr.h"
#include "sa_interface/app_domain_verify_mgr_interface_code.h"
#define private public
#define protected public
#include "app_domain_verify_mgr_client.h"
#include "app_domain_verify_agent_client.h"
#include "sa_interface/app_domain_verify_mgr_service.h"
#undef private
#undef protected
#include "mock_access_token.h"

namespace OHOS::AppDomainVerify {
using ::testing::_;
using ::testing::Invoke;
using ::testing::Mock;
using namespace testing;
using namespace testing::ext;
class AppDomainVerifyMgrModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
auto appDomainVerifyMgrService_ = std::make_shared<AppDomainVerifyMgrService>();
auto appDomainVerifyAgentStubMock_ = std::make_shared<AppDomainVerifyAgentRemoteStubMock>();
int InvokeSingleVerifyOK(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MODULE_BUTT, "call end");
    std::string bundleName = BUNDLE_NAME;
    VerifyResultInfo verifyResultInfo;
    verifyResultInfo.hostVerifyStatusMap.insert_or_assign(
        "https://" + HOST, std::make_tuple(InnerVerifyStatus::STATE_SUCCESS, std::string(), 0));
    appDomainVerifyMgrService_->SaveDomainVerifyStatus(bundleName, verifyResultInfo);
    return 0;
}

int InvokeSingleVerifyFail(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    APP_DOMAIN_VERIFY_HILOGD(APP_DOMAIN_VERIFY_MODULE_BUTT, "call end");
    std::string bundleName = BUNDLE_NAME;
    VerifyResultInfo verifyResultInfo;
    verifyResultInfo.hostVerifyStatusMap.insert_or_assign(
        "https://" + HOST, std::make_tuple(InnerVerifyStatus::STATE_FAIL, std::string(), 0));
    appDomainVerifyMgrService_->SaveDomainVerifyStatus(bundleName, verifyResultInfo);
    return UNKNOWN_ERROR;
}

void AppDomainVerifyMgrModuleTest::SetUpTestCase(void)
{
}

void AppDomainVerifyMgrModuleTest::TearDownTestCase(void)
{
    printf("TearDownTestCase  1\n");
    AppDomainVerifyAgentClient::agentServiceProxy_.ForceSetRefPtr(nullptr);
    printf("TearDownTestCase 2\n");
    AppDomainVerifyAgentClient::DestroyInstance();
    printf("TearDownTestCase 3\n");
    appDomainVerifyMgrService_->appDetailsDataMgr_ = nullptr;
    appDomainVerifyMgrService_->Stop();
    appDomainVerifyAgentStubMock_.reset();
    printf("TearDownTestCase \n");
}

void AppDomainVerifyMgrModuleTest::SetUp(void)
{
    MockAccessToken::mockSA();
    AppDomainVerifyAgentClient::staticDestoryMonitor_.destoryed_ = true;
}

void AppDomainVerifyMgrModuleTest::TearDown(void)
{
}
/**
 * @tc.name: AppDomainVerifyMgrModuleTest001
 * @tc.desc: VerifyDomain ok test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyMgrModuleTest, AppDomainVerifyMgrModuleTest001, TestSize.Level1)
{
    EXPECT_CALL(*appDomainVerifyAgentStubMock_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(::testing::Invoke(InvokeSingleVerifyOK));
    AppDomainVerifyAgentClient::agentServiceProxy_ = sptr<AppDomainVerifyAgentServiceProxy>::MakeSptr(
        appDomainVerifyAgentStubMock_.get());
    std::vector<SkillUri> skillUris;
    SkillUri skillUri;
    skillUri.scheme = "https";
    skillUri.host = HOST;
    skillUris.emplace_back(skillUri);
    appDomainVerifyMgrService_->VerifyDomain(APP_IDENTIFIER, BUNDLE_NAME, FINGERPRINT, skillUris);
    DomainVerifyStatus domainVerificationState;
    auto queryRes = appDomainVerifyMgrService_->QueryDomainVerifyStatus(BUNDLE_NAME, domainVerificationState);
    ASSERT_TRUE(queryRes);
    ASSERT_TRUE(domainVerificationState == DomainVerifyStatus::STATE_VERIFIED);
}

/**
 * @tc.name: AppDomainVerifyMgrModuleTest002
 * @tc.desc: VerifyDomain fail test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyMgrModuleTest, AppDomainVerifyMgrModuleTest002, TestSize.Level1)
{
    EXPECT_CALL(*appDomainVerifyAgentStubMock_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(::testing::Invoke(InvokeSingleVerifyFail));
    AppDomainVerifyAgentClient::agentServiceProxy_ = sptr<AppDomainVerifyAgentServiceProxy>::MakeSptr(
        appDomainVerifyAgentStubMock_.get());

    std::vector<SkillUri> skillUris;
    SkillUri skillUri;
    skillUri.scheme = "https";
    skillUri.host = HOST;
    skillUris.emplace_back(skillUri);
    appDomainVerifyMgrService_->VerifyDomain(APP_IDENTIFIER, BUNDLE_NAME, FINGERPRINT, skillUris);
    DomainVerifyStatus domainVerificationState;
    auto queryRes = appDomainVerifyMgrService_->QueryDomainVerifyStatus(BUNDLE_NAME, domainVerificationState);
    ASSERT_TRUE(queryRes);
    ASSERT_TRUE(domainVerificationState == DomainVerifyStatus::STATE_NONE);
}

/**
 * @tc.name: AppDomainVerifyMgrModuleTest003
 * @tc.desc: FilterAbilities ok test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyMgrModuleTest, AppDomainVerifyMgrModuleTest003, TestSize.Level1)
{
    EXPECT_CALL(*appDomainVerifyAgentStubMock_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(::testing::Invoke(InvokeSingleVerifyOK));
    AppDomainVerifyAgentClient::agentServiceProxy_ = sptr<AppDomainVerifyAgentServiceProxy>::MakeSptr(
        appDomainVerifyAgentStubMock_.get());

    std::vector<SkillUri> skillUris;
    SkillUri skillUri;
    skillUri.scheme = "https";
    skillUri.host = HOST;
    skillUris.emplace_back(skillUri);
    appDomainVerifyMgrService_->VerifyDomain(APP_IDENTIFIER, BUNDLE_NAME, FINGERPRINT, skillUris);
    OHOS::AAFwk::Want want;
    want.SetUri("https://" + HOST);
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME;
    std::vector<OHOS::AppExecFwk::AbilityInfo> originAbilityInfos;
    originAbilityInfos.emplace_back(abilityInfo);
    std::vector<OHOS::AppExecFwk::AbilityInfo> filtedAbilityInfos;
    auto filterRes = appDomainVerifyMgrService_->FilterAbilities(want, originAbilityInfos, filtedAbilityInfos);
    ASSERT_TRUE(filterRes);
    ASSERT_TRUE(!filtedAbilityInfos.empty());
    ASSERT_TRUE(filtedAbilityInfos[0].bundleName == BUNDLE_NAME);
}

/**
 * @tc.name: AppDomainVerifyMgrModuleTest004
 * @tc.desc: FilterAbilities fail test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyMgrModuleTest, AppDomainVerifyMgrModuleTest004, TestSize.Level1)
{
    EXPECT_CALL(*appDomainVerifyAgentStubMock_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(::testing::Invoke(InvokeSingleVerifyFail));
    AppDomainVerifyAgentClient::agentServiceProxy_ = sptr<AppDomainVerifyAgentServiceProxy>::MakeSptr(
        appDomainVerifyAgentStubMock_.get());
    std::vector<SkillUri> skillUris;
    SkillUri skillUri;
    skillUri.scheme = "https";
    skillUri.host = HOST;
    skillUris.emplace_back(skillUri);
    appDomainVerifyMgrService_->VerifyDomain(APP_IDENTIFIER, BUNDLE_NAME, FINGERPRINT, skillUris);

    OHOS::AAFwk::Want want;
    want.SetUri("https://" + HOST);
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME;
    std::vector<OHOS::AppExecFwk::AbilityInfo> originAbilityInfos;
    originAbilityInfos.emplace_back(abilityInfo);

    std::vector<OHOS::AppExecFwk::AbilityInfo> filtedAbilityInfos;
    auto filterRes = appDomainVerifyMgrService_->FilterAbilities(want, originAbilityInfos, filtedAbilityInfos);
    ASSERT_TRUE(filterRes);
    ASSERT_TRUE(filtedAbilityInfos.empty());
}

/**
 * @tc.name: AppDomainVerifyMgrModuleTest005
 * @tc.desc: FilterAbilities fail test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyMgrModuleTest, AppDomainVerifyMgrModuleTest005, TestSize.Level1)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(BUNDLE_NAME, "MainAbility");
    want.SetUri("https://" + HOST);
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME;
    std::vector<OHOS::AppExecFwk::AbilityInfo> originAbilityInfos;
    originAbilityInfos.emplace_back(abilityInfo);

    std::vector<OHOS::AppExecFwk::AbilityInfo> filtedAbilityInfos;
    auto filterRes = appDomainVerifyMgrService_->FilterAbilities(want, originAbilityInfos, filtedAbilityInfos);
    ASSERT_FALSE(filterRes);
    ASSERT_TRUE(filtedAbilityInfos.empty());
}

/**
 * @tc.name: AppDomainVerifyMgrModuleTest006
 * @tc.desc: QueryDomainVerifyStatus test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyMgrModuleTest, AppDomainVerifyMgrModuleTest006, TestSize.Level1)
{
    DomainVerifyStatus domainVerificationState;
    auto queryRes = appDomainVerifyMgrService_->QueryDomainVerifyStatus(BUNDLE_NAME, domainVerificationState);
    ASSERT_TRUE(queryRes);
    ASSERT_TRUE(domainVerificationState == DomainVerifyStatus::STATE_NONE);
}
}
