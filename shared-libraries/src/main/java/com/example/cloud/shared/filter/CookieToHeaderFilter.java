package com.example.cloud.shared.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.util.WebUtils;

public class CookieToHeaderFilter extends ZuulFilter {

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletRequest request = context.getRequest();
	return request.getHeader(HttpHeaders.AUTHORIZATION) == null &&
                WebUtils.getCookie(request, OAuth2AccessToken.ACCESS_TOKEN) != null &&
                WebUtils.getCookie(request, OAuth2AccessToken.REFRESH_TOKEN) != null;
    }

    @Override
    public Object run() {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletRequest request = context.getRequest();
        Cookie cookie = WebUtils.getCookie(request, OAuth2AccessToken.ACCESS_TOKEN);
        context.addZuulRequestHeader(HttpHeaders.AUTHORIZATION, OAuth2AccessToken.BEARER_TYPE + " " + cookie.getValue());
        return null;
    }
    
}
