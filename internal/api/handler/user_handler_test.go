package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/d60-Lab/gin-template/internal/dto"
	"github.com/d60-Lab/gin-template/internal/service"
	"github.com/d60-Lab/gin-template/pkg/validator"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMain(m *testing.M) {
	// 初始化自定义验证器
	validator.Init()

	// 运行测试
	code := m.Run()
	os.Exit(code)
}

// MockUserService 模拟用户服务
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Create(ctx context.Context, req *dto.CreateUserRequest) (*dto.UserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.UserResponse), args.Error(1)
}

func (m *MockUserService) GetByID(ctx context.Context, id string) (*dto.UserResponse, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.UserResponse), args.Error(1)
}

func (m *MockUserService) Update(ctx context.Context, id string, req *dto.UpdateUserRequest) (*dto.UserResponse, error) {
	args := m.Called(ctx, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.UserResponse), args.Error(1)
}

func (m *MockUserService) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.LoginResponse), args.Error(1)
}

func (m *MockUserService) List(ctx context.Context, page, pageSize int) ([]*dto.UserResponse, error) {
	args := m.Called(ctx, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*dto.UserResponse), args.Error(1)
}

func TestGetUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockUserService)
	handler := NewHandler(mockService)

	expectedUser := &dto.UserResponse{
		ID:       "1",
		Username: "testuser",
		Email:    "test@example.com",
	}

	mockService.On("GetByID", mock.Anything, "1").Return(expectedUser, nil)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.GET("/users/:id", handler.GetUser)

	req, _ := http.NewRequest("GET", "/users/1", nil)
	c.Request = req

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockService.AssertExpectations(t)
}

func TestCreateUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockUserService)
	handler := NewHandler(mockService)

	createReq := &dto.CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	expectedUser := &dto.UserResponse{
		ID:       "1",
		Username: "testuser",
		Email:    "test@example.com",
	}

	mockService.On("Create", mock.Anything, createReq).Return(expectedUser, nil)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.POST("/users", handler.CreateUser)

	jsonData, _ := json.Marshal(createReq)
	req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockService.AssertExpectations(t)
}

func TestGetUserNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockUserService)
	handler := NewHandler(mockService)

	mockService.On("GetByID", mock.Anything, "999").Return(nil, service.ErrUserNotFound)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.GET("/users/:id", handler.GetUser)

	req, _ := http.NewRequest("GET", "/users/999", nil)
	c.Request = req

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockService.AssertExpectations(t)
}
