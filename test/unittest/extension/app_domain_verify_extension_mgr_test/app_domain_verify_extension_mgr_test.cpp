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

#include "gtest/gtest.h"

#define private public
#define protected public

#include "app_domain_verify_extension_mgr.h"
#include "app_domain_verify_extension_register.h"
#undef private
#undef protected
#include "app_domain_verify_hilog.h"
#include "mock_app_domain_verify_extension_mgr.h"
#include "app_domain_verify_agent_ext.h"
#include "mock_convert_callback.h"

namespace OHOS::AppDomainVerify {
using namespace testing;
using namespace testing::ext;
class AppDomainVerifyAgentExtImpl : public AppDomainVerifyAgentExt {
public:
    AppDomainVerifyAgentExtImpl() = default;
    virtual ~AppDomainVerifyAgentExtImpl() = default;
};

class AppDomainVerifyExtensionMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void AppDomainVerifyExtensionMgrTest::SetUpTestCase(void)
{
}

void AppDomainVerifyExtensionMgrTest::TearDownTestCase(void)
{
}

void AppDomainVerifyExtensionMgrTest::SetUp(void)
{
}

void AppDomainVerifyExtensionMgrTest::TearDown(void)
{
}

/**
 * @tc.name: AppDomainVerifySingleVerifyTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifySingleVerifyTest001, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(false));

    const AppVerifyBaseInfo appVerifyBaseInfo;
    VerifyResultInfo verifyResultInfo;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.SingleVerify(appVerifyBaseInfo, verifyResultInfo) ==
        ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}
/**
 * @tc.name: AppDomainVerifySingleVerifyTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifySingleVerifyTest002, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(nullptr));

    const AppVerifyBaseInfo appVerifyBaseInfo;
    VerifyResultInfo verifyResultInfo;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.SingleVerify(appVerifyBaseInfo, verifyResultInfo) ==
        ErrorCode::E_EXTENSIONS_INTERNAL_ERROR);
}
/**
 * @tc.name: AppDomainVerifySingleVerifyTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifySingleVerifyTest003, TestSize.Level0)
{
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest007");
    std::shared_ptr<AppDomainVerifyAgentExt> appDomainVerifyAgentExt = std::make_shared<AppDomainVerifyAgentExtImpl>();
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(appDomainVerifyAgentExt));

    const AppVerifyBaseInfo appVerifyBaseInfo;
    VerifyResultInfo verifyResultInfo;
    ErrorCode ret = appDomainVerifyExtensionMgr.SingleVerify(appVerifyBaseInfo, verifyResultInfo);
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "ret %d\n", ret);
    printf("ret %d\n", ret);
    ASSERT_TRUE(ret == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest007 end");
}
/**
 * @tc.name: AppDomainVerifyCompleteVerifyTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyCompleteVerifyTest001, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(false));

    const BundleVerifyStatusInfo bundleVerifyStatusInfo;
    TaskType type = IMMEDIATE_TASK;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.CompleteVerifyRefresh(bundleVerifyStatusInfo, type) ==
        ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}

/**
 * @tc.name: AppDomainVerifyCompleteVerifyTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyCompleteVerifyTest002, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(nullptr));

    const BundleVerifyStatusInfo bundleVerifyStatusInfo;
    int delaySeconds = 0;
    TaskType type = IMMEDIATE_TASK;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.CompleteVerifyRefresh(bundleVerifyStatusInfo, type) ==
        ErrorCode::E_EXTENSIONS_INTERNAL_ERROR);
}

/**
 * @tc.name: AppDomainVerifyCompleteVerifyTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyCompleteVerifyTest003, TestSize.Level0)
{
    std::shared_ptr<AppDomainVerifyAgentExt> appDomainVerifyAgentExt = std::make_shared<AppDomainVerifyAgentExtImpl>();
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(appDomainVerifyAgentExt));

    OHOS::AAFwk::Want atomicWant;
    sptr<IConvertCallback> cb = new MocConvertCallback;
    ASSERT_TRUE(
        appDomainVerifyExtensionMgr.ConvertToExplicitWant(atomicWant, cb) == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}

/**
 * @tc.name: AppDomainVerifyConvertTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyConvertTest001, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(false));

    OHOS::AAFwk::Want atomicWant;
    sptr<IConvertCallback> cb = new MocConvertCallback;
    ASSERT_TRUE(
        appDomainVerifyExtensionMgr.ConvertToExplicitWant(atomicWant, cb) == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}

/**
 * @tc.name: AppDomainVerifyConvertTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyConvertTest002, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(nullptr));

    OHOS::AAFwk::Want atomicWant;
    sptr<IConvertCallback> cb = new MocConvertCallback;
    ASSERT_TRUE(
        appDomainVerifyExtensionMgr.ConvertToExplicitWant(atomicWant, cb) == ErrorCode::E_EXTENSIONS_INTERNAL_ERROR);
}

/**
 * @tc.name: AppDomainVerifyConvertTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyConvertTest003, TestSize.Level0)
{
    std::shared_ptr<AppDomainVerifyAgentExt> appDomainVerifyAgentExt = std::make_shared<AppDomainVerifyAgentExtImpl>();
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(appDomainVerifyAgentExt));

    const BundleVerifyStatusInfo bundleVerifyStatusInfo;
    int delaySeconds = 0;
    TaskType type = IMMEDIATE_TASK;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.CompleteVerifyRefresh(bundleVerifyStatusInfo, type) ==
        ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}
/**
 * @tc.name: AppDomainVerifyUpdateWhiteListTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyUpdateWhiteListTest001, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(false));

    OHOS::AAFwk::Want atomicWant;
    sptr<IConvertCallback> cb = new MocConvertCallback;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.UpdateWhiteList() == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}

/**
 * @tc.name: AppDomainVerifyUpdateWhiteListTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyUpdateWhiteListTest002, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(nullptr));

    ASSERT_TRUE(appDomainVerifyExtensionMgr.UpdateWhiteList() == ErrorCode::E_EXTENSIONS_INTERNAL_ERROR);
}

/**
 * @tc.name: AppDomainVerifyUpdateWhiteListTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyUpdateWhiteListTest003, TestSize.Level0)
{
    std::shared_ptr<AppDomainVerifyAgentExt> appDomainVerifyAgentExt = std::make_shared<AppDomainVerifyAgentExtImpl>();
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(appDomainVerifyAgentExt));

    ASSERT_TRUE(appDomainVerifyExtensionMgr.UpdateWhiteList() == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}
/**
 * @tc.name: AppDomainVerifyUpdateAppDetailsTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyUpdateAppDetailsTest001, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(false));

    OHOS::AAFwk::Want atomicWant;
    sptr<IConvertCallback> cb = new MocConvertCallback;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.UpdateAppDetails() == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}

/**
 * @tc.name: AppDomainVerifyUpdateAppDetailsTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyUpdateAppDetailsTest002, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(nullptr));

    ASSERT_TRUE(appDomainVerifyExtensionMgr.UpdateAppDetails() == ErrorCode::E_EXTENSIONS_INTERNAL_ERROR);
}

/**
 * @tc.name: AppDomainVerifyUpdateAppDetailsTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyUpdateAppDetailsTest003, TestSize.Level0)
{
    std::shared_ptr<AppDomainVerifyAgentExt> appDomainVerifyAgentExt = std::make_shared<AppDomainVerifyAgentExtImpl>();
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(appDomainVerifyAgentExt));

    ASSERT_TRUE(appDomainVerifyExtensionMgr.UpdateAppDetails() == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}
/**
 * @tc.name: AppDomainVerifyCommonTransactTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyCommonTransactTest001, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(false));

    OHOS::AAFwk::Want atomicWant;
    sptr<IConvertCallback> cb = new MocConvertCallback;
    std::string request;
    std::string response;
    ASSERT_TRUE(
        appDomainVerifyExtensionMgr.CommonTransact(0, request, response) == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}

/**
 * @tc.name: AppDomainVerifyCommonTransactTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyCommonTransactTest002, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(nullptr));
    std::string request;
    std::string response;
    ASSERT_TRUE(
        appDomainVerifyExtensionMgr.CommonTransact(0, request, response) == ErrorCode::E_EXTENSIONS_INTERNAL_ERROR);
}

/**
 * @tc.name: AppDomainVerifyCommonTransactTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyCommonTransactTest003, TestSize.Level0)
{
    std::shared_ptr<AppDomainVerifyAgentExt> appDomainVerifyAgentExt = std::make_shared<AppDomainVerifyAgentExtImpl>();
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    EXPECT_CALL(appDomainVerifyExtensionMgr, Init()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(appDomainVerifyExtensionMgr, GetAppDomainVerifyExt(APP_DOMAIN_VERIFY_AGENT_EXT_NAME))
        .Times(1)
        .WillOnce(Return(appDomainVerifyAgentExt));

    std::string request;
    std::string response;
    ASSERT_TRUE(
        appDomainVerifyExtensionMgr.CommonTransact(0, request, response) == ErrorCode::E_EXTENSIONS_LIB_NOT_FOUND);
}
/**
 * @tc.name: AppDomainVerifyExtensionMgrTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionMgrTest001, TestSize.Level0)
{
    AppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.GetAppDomainVerifyExt("test") == nullptr);
}
/**
 * @tc.name: AppDomainVerifyExtensionMgrTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionMgrTest002, TestSize.Level0)
{
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest006");
    MockAppDomainVerifyExtensionMgr1 appDomainVerifyExtensionMgr;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.Init() == false);

    EXPECT_CALL(appDomainVerifyExtensionMgr, OpenLib()).Times(1).WillOnce(Return(nullptr));
    ASSERT_TRUE(appDomainVerifyExtensionMgr.Init() == false);
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest006 end");
}

/**
 * @tc.name: AppDomainVerifyExtensionMgrTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionMgrTest003, TestSize.Level0)
{
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest007");
    MockAppDomainVerifyExtensionMgr1 appDomainVerifyExtensionMgr;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.Init() == false);

    int temp = 5;
    EXPECT_CALL(appDomainVerifyExtensionMgr, OpenLib()).Times(1).WillOnce(Return(&temp));
    ASSERT_TRUE(appDomainVerifyExtensionMgr.Init() == true);
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest007 end");
}

/**
 * @tc.name: AppDomainVerifyExtensionMgrTest004
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionMgrTest004, TestSize.Level0)
{
    MockAppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.OpenLib() == nullptr);
}

/**
 * @tc.name: AppDomainVerifyExtensionMgrTest005
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionMgrTest005, TestSize.Level0)
{
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest011");
    int a = 5;
    AppDomainVerifyExtensionMgr::sHandler = &a;
    MockAppDomainVerifyExtensionMgr1 appDomainVerifyExtensionMgr;
    ASSERT_TRUE(appDomainVerifyExtensionMgr.Init() == true);
    APP_DOMAIN_VERIFY_HILOGE(APP_DOMAIN_VERIFY_MODULE_EXTENSION, "AppDomainVerifyExtensionMgrTest011 end");
}
/**
 * @tc.name: AppDomainVerifyExtensionRegisterTest001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionRegisterTest001, TestSize.Level0)
{
    AppDomainVerifyExtensionRegister appDomainVerifyExtensionRegister;

    appDomainVerifyExtensionRegister.RegisterAppDomainVerifyExt("test",
        []() -> std::shared_ptr<AppDomainVerifyAgentExt> { return std::make_shared<AppDomainVerifyAgentExtImpl>(); });

    ASSERT_TRUE(appDomainVerifyExtensionRegister.GetAppDomainVerifyExt("test") != nullptr);
}
/**
 * @tc.name: AppDomainVerifyExtensionRegisterTest002
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionRegisterTest002, TestSize.Level0)
{
    AppDomainVerifyExtensionRegister appDomainVerifyExtensionRegister;
    appDomainVerifyExtensionRegister.RegisterAppDomainVerifyExt("test",
        []() -> std::shared_ptr<AppDomainVerifyAgentExt> { return std::make_shared<AppDomainVerifyAgentExtImpl>(); });

    ASSERT_TRUE(appDomainVerifyExtensionRegister.GetAppDomainVerifyExt("test1") == nullptr);
}
/**
 * @tc.name: AppDomainVerifyExtensionRegisterTest003
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionRegisterTest003, TestSize.Level0)
{
    AppDomainVerifyExtensionRegister appDomainVerifyExtensionRegister;

    ASSERT_TRUE(appDomainVerifyExtensionRegister.GetAppDomainVerifyExt("test") == nullptr);
}

/**
 * @tc.name: AppDomainVerifyExtensionMgr001
 * @tc.desc: ExtensionMgr test.
 * @tc.type: FUNC
 */
HWTEST_F(AppDomainVerifyExtensionMgrTest, AppDomainVerifyExtensionMgr001, TestSize.Level0)
{
    AppDomainVerifyExtensionMgr appDomainVerifyExtensionMgr;
    auto ret = appDomainVerifyExtensionMgr.UpdateAppDetails();
    ASSERT_EQ(ret, ErrorCode::E_EXTENSIONS_INTERNAL_ERROR);
}
}