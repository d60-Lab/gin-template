package validator

import (
	"strings"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// Init 初始化自定义验证器
func Init() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		// 注册自定义验证规则
		if err := v.RegisterValidation("username", validateUsername); err != nil {
			panic(err)
		}
	}
}

// validateUsername 自定义用户名验证规则
func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	// 用户名长度至少3个字符，且不包含空格
	return len(username) >= 3 && !strings.Contains(username, " ")
}
