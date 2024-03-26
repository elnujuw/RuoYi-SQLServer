package com.ruoyi.framework.jimu;

import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.framework.web.service.TokenService;
import com.ruoyi.system.service.ISysUserService;
import org.jeecg.modules.jmreport.api.JmReportTokenServiceI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


@Component
public class JimuReportTokenService implements JmReportTokenServiceI  {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private ISysUserService iSysUserService;


    @Override
    public String getUsername(String token) {
        LoginUser loginUser = tokenService.getLoginUser(token);
        return loginUser.getUsername();
    }

    @Override
    public String[] getRoles(String s) {
        return new String[0];
    }

    //    校验token
    @Override
    public Boolean verifyToken(String token) {
        LoginUser loginUser = tokenService.getLoginUser(token);
        if (StringUtils.isNotNull(loginUser)) {
            // 刷新token有效期
            tokenService.refreshToken(loginUser);
            // 超管不需要鉴权
            if (loginUser.getUser() != null && loginUser.getUser().isAdmin()) {
                return true;
            } else {
                // 校验菜单权限
                Set<String> permissions = loginUser.getPermissions();
                return permissions != null &&
                        (permissions.contains("report:jimu:design")
                                || permissions.contains("report:jimu:view"));
            }
        }
        return false;
    }

    @Override
    public String getToken(HttpServletRequest request) {
        String token = request.getParameter("token");
        if (StringUtils.isEmpty(token)) {
            token = request.getHeader("token");
        }
        LoginUser loginUser = tokenService.getLoginUser(token);
        if (loginUser != null) {
            return token;
        }
        return "";
    }

    @Override
    public String getToken() {
        return JmReportTokenServiceI.super.getToken();
    }

    @Override
    public Map<String, Object> getUserInfo(String token) {
        Map<String, Object> map = new HashMap(5);
        LoginUser loginUser = tokenService.getLoginUser(token);
        //设置用户名
        map.put(SYS_USER_CODE, loginUser.getUsername());
        //设置部门编码
        map.put(SYS_ORG_CODE, loginUser.getDeptId());
        // 将所有信息存放至map 解析sql/api会根据map的键值解析
        return map;
    }

    @Override
    public HttpHeaders customApiHeader() {
        HttpHeaders header = new HttpHeaders();
        // 主要用于API数据源。默认给API数据源的header中携带上Token
        // 如使用当前项目的API，则需要再header中携带Authorization头
        header.add("token", getToken());
        header.add("X-Access-Token", getToken());
        return header;
    }

    @Override
    public String getTenantId() {
        return JmReportTokenServiceI.super.getTenantId();
    }

}
