package repository

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/d60-Lab/gin-template/internal/model"
)

// UserRepositoryTestSuite 用户仓储测试套件
type UserRepositoryTestSuite struct {
	suite.Suite
	db   *gorm.DB
	repo UserRepository
}

// SetupSuite 测试套件初始化
func (suite *UserRepositoryTestSuite) SetupSuite() {
	// 使用 SQLite 内存数据库进行测试
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(suite.T(), err)

	// 自动迁移
	err = db.AutoMigrate(&model.User{})
	assert.NoError(suite.T(), err)

	suite.db = db
	suite.repo = NewUserRepository(db)
}

// TearDownTest 每个测试后清理数据
func (suite *UserRepositoryTestSuite) TearDownTest() {
	suite.db.Exec("DELETE FROM users")
}

// TestCreate 测试创建用户
func (suite *UserRepositoryTestSuite) TestCreate() {
	ctx := context.Background()
	user := &model.User{
		ID:       "test-id-1",
		Username: "testuser",
		Email:    "test@example.com",
		Password: "hashedpassword", // pragma: allowlist secret
		Age:      25,
	}

	err := suite.repo.Create(ctx, user)
	assert.NoError(suite.T(), err)

	// 验证用户已创建
	var count int64
	suite.db.Model(&model.User{}).Where("id = ?", user.ID).Count(&count)
	assert.Equal(suite.T(), int64(1), count)
}

// TestGetByID 测试根据ID获取用户
func (suite *UserRepositoryTestSuite) TestGetByID() {
	ctx := context.Background()

	// 先创建一个用户
	user := &model.User{
		ID:       "test-id-2",
		Username: "testuser2",
		Email:    "test2@example.com",
		Password: "hashedpassword", // pragma: allowlist secret
		Age:      30,
	}
	err := suite.repo.Create(ctx, user)
	assert.NoError(suite.T(), err)

	// 获取用户
	found, err := suite.repo.GetByID(ctx, user.ID)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), found)
	assert.Equal(suite.T(), user.Username, found.Username)
	assert.Equal(suite.T(), user.Email, found.Email)
}

// TestGetByIDNotFound 测试获取不存在的用户
func (suite *UserRepositoryTestSuite) TestGetByIDNotFound() {
	ctx := context.Background()
	found, err := suite.repo.GetByID(ctx, "non-existent-id")
	assert.NoError(suite.T(), err)
	assert.Nil(suite.T(), found)
}

// TestGetByUsername 测试根据用户名获取用户
func (suite *UserRepositoryTestSuite) TestGetByUsername() {
	ctx := context.Background()

	user := &model.User{
		ID:       "test-id-3",
		Username: "testuser3",
		Email:    "test3@example.com",
		Password: "hashedpassword", // pragma: allowlist secret
	}
	err := suite.repo.Create(ctx, user)
	assert.NoError(suite.T(), err)

	found, err := suite.repo.GetByUsername(ctx, user.Username)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), found)
	assert.Equal(suite.T(), user.ID, found.ID)
	assert.Equal(suite.T(), user.Email, found.Email)
}

// TestGetByEmail 测试根据邮箱获取用户
func (suite *UserRepositoryTestSuite) TestGetByEmail() {
	ctx := context.Background()

	user := &model.User{
		ID:       "test-id-4",
		Username: "testuser4",
		Email:    "test4@example.com",
		Password: "hashedpassword", // pragma: allowlist secret
	}
	err := suite.repo.Create(ctx, user)
	assert.NoError(suite.T(), err)

	found, err := suite.repo.GetByEmail(ctx, user.Email)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), found)
	assert.Equal(suite.T(), user.ID, found.ID)
	assert.Equal(suite.T(), user.Username, found.Username)
}

// TestUpdate 测试更新用户
func (suite *UserRepositoryTestSuite) TestUpdate() {
	ctx := context.Background()

	user := &model.User{
		ID:       "test-id-5",
		Username: "testuser5",
		Email:    "test5@example.com",
		Password: "hashedpassword", // pragma: allowlist secret
		Age:      25,
	}
	err := suite.repo.Create(ctx, user)
	assert.NoError(suite.T(), err)

	// 更新用户
	user.Username = "updateduser"
	user.Age = 30
	err = suite.repo.Update(ctx, user)
	assert.NoError(suite.T(), err)

	// 验证更新
	found, err := suite.repo.GetByID(ctx, user.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "updateduser", found.Username)
	assert.Equal(suite.T(), 30, found.Age)
}

// TestDelete 测试删除用户
func (suite *UserRepositoryTestSuite) TestDelete() {
	ctx := context.Background()

	user := &model.User{
		ID:       "test-id-6",
		Username: "testuser6",
		Email:    "test6@example.com",
		Password: "hashedpassword", // pragma: allowlist secret
	}
	err := suite.repo.Create(ctx, user)
	assert.NoError(suite.T(), err)

	// 删除用户
	err = suite.repo.Delete(ctx, user.ID)
	assert.NoError(suite.T(), err)

	// 验证已删除
	found, err := suite.repo.GetByID(ctx, user.ID)
	assert.NoError(suite.T(), err)
	assert.Nil(suite.T(), found)
}

// TestList 测试获取用户列表
func (suite *UserRepositoryTestSuite) TestList() {
	ctx := context.Background()

	// 创建多个用户
	for i := 1; i <= 15; i++ {
		user := &model.User{
			ID:       "test-id-" + string(rune(i)),
			Username: "testuser" + string(rune(i)),
			Email:    "test" + string(rune(i)) + "@example.com",
			Password: "hashedpassword", // pragma: allowlist secret
		}
		err := suite.repo.Create(ctx, user)
		assert.NoError(suite.T(), err)
	}

	// 测试分页
	users, err := suite.repo.List(ctx, 0, 10)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 10, len(users))

	// 测试第二页
	users, err = suite.repo.List(ctx, 10, 10)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 5, len(users))
}

// TestUserRepositorySuite 运行测试套件
func TestUserRepositorySuite(t *testing.T) {
	suite.Run(t, new(UserRepositoryTestSuite))
}
