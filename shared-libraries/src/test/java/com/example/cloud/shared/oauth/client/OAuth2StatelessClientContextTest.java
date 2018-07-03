package com.example.cloud.shared.oauth.client;

import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.test.util.ReflectionTestUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class OAuth2StatelessClientContextTest {

    @Test
    public void constructsWithDefaultPrefixAndContext() {
        OAuth2StatelessClientContext context = contextBuilder("", "").build();
        assertThat(ReflectionTestUtils.getField(context, "contextPath")).isEqualTo("/");
        assertThat(ReflectionTestUtils.getField(context, "stateCookieName")).isEqualTo("state");
        assertThat(ReflectionTestUtils.getField(context, "accessTokenCookieName")).isEqualTo(OAuth2AccessToken.ACCESS_TOKEN);
        assertThat(ReflectionTestUtils.getField(context, "refreshTokenCookieName")).isEqualTo(OAuth2AccessToken.REFRESH_TOKEN);
    }

    private OAuth2StatelessClientContext.OAuth2StatelessClientContextBuilder contextBuilder(String prefix, String contextPath) {
        ServletContext servletContext = Mockito.mock(ServletContext.class);
        Mockito.when(servletContext.getContextPath()).thenReturn(contextPath);
        return OAuth2StatelessClientContext.builder()
                .servletContext(servletContext)
                .prefix(prefix);
    }

    @Test
    public void constructsWithSpecifiedPrefixAndContext() {
        OAuth2StatelessClientContext context = contextBuilder("prefix","/path").build();
        assertThat(ReflectionTestUtils.getField(context, "contextPath")).isEqualTo("/path");
        assertThat(ReflectionTestUtils.getField(context, "stateCookieName")).isEqualTo("prefix_state");
        assertThat(ReflectionTestUtils.getField(context, "accessTokenCookieName")).isEqualTo("prefix_" + OAuth2AccessToken.ACCESS_TOKEN);
        assertThat(ReflectionTestUtils.getField(context, "refreshTokenCookieName")).isEqualTo("prefix_" + OAuth2AccessToken.REFRESH_TOKEN);
    }

    @Test
    public void setNullAccessToken() {
        testSetAccessToken(null, null,"", 2);
    }

    private void testSetAccessToken(String accessTokenValue, String refreshTokenValue, String expectedCookieValue, int setTimes) {

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(false);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        OAuth2StatelessClientContext context = contextBuilder("", "")
                .request(request)
                .response(response)
                .build();

        DefaultOAuth2AccessToken accessToken = accessTokenValue == null ? null : new DefaultOAuth2AccessToken(accessTokenValue);
        if (refreshTokenValue != null) accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshTokenValue));

        context.setAccessToken(accessToken);
        Mockito.verify(response, Mockito.times(setTimes)).addCookie(ArgumentMatchers.argThat(cookie -> {
            assertThat(cookie.getValue()).isEqualTo(expectedCookieValue);
            return true;
        }));

    }

    @Test
    public void setAccessTokenWithoutRefresh() {
        testSetAccessToken("token-value", null,"token-value", 1);
    }

    @Test
    public void setAccessTokenAndRefresh() {
        testSetAccessToken("token-value", "token-value","token-value", 2);
    }

    @Test
    public void getAccessToken() {
    }

    @Test
    public void setPreservedState() {
    }

    @Test
    public void removePreservedState() {
    }

    @Test
    public void getAccessTokenRequest() {
    }
}