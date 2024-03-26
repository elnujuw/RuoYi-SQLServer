package com.ruoyi.framework.jimu;

import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.utils.ServletUtils;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.framework.web.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

@Component
public class JimuInterceptor implements HandlerInterceptor {

    @Autowired
    private TokenService tokenService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getParameter("token");
        if (StringUtils.isEmpty(token)) {
            token = request.getHeader("Token");
        }
        LoginUser loginUser = tokenService.getLoginUser(token);
        if (loginUser != null) {
            // 超级管理员无需鉴权
            if (loginUser.getUser() != null && loginUser.getUser().isAdmin()) {
                return true;
            } else {
                // 获取权限集合
                Set<String> permissions = loginUser.getPermissions();
                // 如果拥有设计器的权限，则无需view权限也可以通过校验
                if (permissions != null && permissions.contains("report:jimu:design")) {
                    return true;
                }
                // 其余情况，一般是通过报表菜单点击进来的，校验对应报表的权限：report:jimu:view:{reportId}
                // http://.../jmreport/view/1234567890，则reportId = 1234567890
                String reportId = StringUtils.substringAfterLast(request.getRequestURI(), "/");
                String viewPerm = "report:jimu:view:" + reportId;
                if (permissions != null && permissions.contains(viewPerm)) {
                    return true;
                }
            }
        }
        AjaxResult ajaxResult = AjaxResult.error("参数错误或没有改报表的访问权限！");
        ServletUtils.renderString(response, JSONObject.toJSONString(ajaxResult));
        return false;
    }
}
