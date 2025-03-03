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
#include <memory>
#include "mock_ffrt/ffrt.h"
#include "mock_constant.h"
#include "rdb_helper.h"
#define private public
#define protected public
#include "app_domain_verify_rdb_open_callback.h"
#undef private
#undef protected

namespace OHOS::AppDomainVerify {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
class RdbOpenCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RdbOpenCallbackTest::SetUpTestCase(void)
{
}

void RdbOpenCallbackTest::TearDownTestCase(void)
{
}

void RdbOpenCallbackTest::SetUp(void)
{
}

void RdbOpenCallbackTest::TearDown(void)
{
}
/**
 * @tc.name: RdbOpenCallbackTest001
 * @tc.desc: Callback test
 * @tc.type: FUNC
 */
HWTEST_F(RdbOpenCallbackTest, RdbOpenCallbackTest001, TestSize.Level0)
{
    AppDomainVerifyRdbConfig rdbConfig;
    rdbConfig.dbName = Constants::RDB_NAME;
    rdbConfig.tableName = Constants::RDB_TABLE_NAME;
    NativeRdb::RdbStoreConfig rdbStoreConfig(rdbConfig.dbPath + rdbConfig.dbName);
    rdbStoreConfig.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    AppDomainVerifyRdbOpenCallback appDomainVerifyRdbOpenCallback(rdbConfig);
    auto rdbStored = NativeRdb::RdbHelper::GetRdbStore(
        rdbStoreConfig, rdbConfig.version, appDomainVerifyRdbOpenCallback, errCode);
    ASSERT_TRUE(appDomainVerifyRdbOpenCallback.OnCreate(*rdbStored) == NativeRdb::E_OK);
    ASSERT_TRUE(appDomainVerifyRdbOpenCallback.OnUpgrade(*rdbStored, 3, 3) == NativeRdb::E_OK);
    ASSERT_TRUE(appDomainVerifyRdbOpenCallback.OnDowngrade(*rdbStored, 2, 1) == NativeRdb::E_OK);
    ASSERT_TRUE(appDomainVerifyRdbOpenCallback.onCorruption("") == NativeRdb::E_OK);
}

}