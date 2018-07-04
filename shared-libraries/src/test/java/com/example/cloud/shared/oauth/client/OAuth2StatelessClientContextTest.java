package com.example.cloud.shared.oauth.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.util.ReflectionTestUtils;

import javax.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

import static org.assertj.core.api.AssertionsForClassTypes.*;
import static org.mockito.ArgumentMatchers.*;

public class OAuth2StatelessClientContextTest {

    private OAuth2StatelessClientContext context;

    @Before
    public void setUp() {
        context = contextBuilder("", "").build();
    }

    private OAuth2StatelessClientContext.OAuth2StatelessClientContextBuilder contextBuilder(String prefix, String contextPath) {
        MockServletContext servletContext = new MockServletContext();
        servletContext.setContextPath(contextPath);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSecure(true);
        return OAuth2StatelessClientContext.builder()
                .request(request)
                .response(new MockHttpServletResponse())
                .servletContext(servletContext)
                .objectMapper(Mockito.mock(ObjectMapper.class))
                .tokenStore(Mockito.mock(TokenStore.class))
                .prefix(prefix);
    }

    @Test
    public void constructsWithDefaultPrefixAndContext() {
        assertThat(ReflectionTestUtils.getField(context, "contextPath")).isEqualTo("/");
        assertThat(ReflectionTestUtils.getField(context, "stateCookieName")).isEqualTo("state");
        assertThat(ReflectionTestUtils.getField(context, "accessTokenCookieName")).isEqualTo(OAuth2AccessToken.ACCESS_TOKEN);
        assertThat(ReflectionTestUtils.getField(context, "refreshTokenCookieName")).isEqualTo(OAuth2AccessToken.REFRESH_TOKEN);
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
        testSetAccessToken(null, null);
    }

    private void testSetAccessToken(String accessTokenValue, String refreshTokenValue) {

        DefaultOAuth2AccessToken accessToken = accessTokenValue == null ? null : new DefaultOAuth2AccessToken(accessTokenValue);
        if (refreshTokenValue != null) accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshTokenValue));

        context.setAccessToken(accessToken);

        assertThat(ReflectionTestUtils.getField(context, "currentAccessToken")).isSameAs(accessToken);

        Cookie[] cookies = ((MockHttpServletResponse) context.getResponse()).getCookies();
        Map<String, Cookie> cookieMap = Arrays.stream(cookies).collect(HashMap::new,
                (map, cookie) -> map.put(cookie.getName(), cookie), HashMap::putAll);

        Cookie accessCookie = cookieMap.get(OAuth2AccessToken.ACCESS_TOKEN);
        Cookie refreshCookie = cookieMap.get(OAuth2AccessToken.REFRESH_TOKEN);

        assertThat(accessCookie).isNotNull();
        if (accessToken == null) {
            checkCookie(accessCookie, "", 0);
            checkCookie(refreshCookie, "", 0);
            return;
        }

        checkCookie(accessCookie, accessTokenValue, -1);
        if (refreshTokenValue != null) checkCookie(refreshCookie, refreshTokenValue, -1);

    }

    private void checkCookie(Cookie cookie, String value, int maxAge) {
        assertThat(cookie.getValue()).isEqualTo(value);
        assertThat(cookie.getMaxAge()).isEqualTo(maxAge);
    }

    @Test
    public void setAccessTokenWithoutRefresh() {
        testSetAccessToken("access-token", null);
    }

    @Test
    public void setAccessTokenAndRefresh() {
        testSetAccessToken("access-token", "refresh-token");
    }

    @Test
    public void getAccessTokenFromCurrent() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("access-token");
        ReflectionTestUtils.setField(context, "currentAccessToken", token);
        assertThat(context.getAccessToken()).isSameAs(token);
    }

    @Test
    public void getAccessTokenFromAbsentCookie() {
        assertThat(context.getAccessToken()).isNull();
    }

    @Test
    public void getAccessTokenFromCookie() {
        testGetAccessTokenFromCookie("access-token", null);
    }

    private void testGetAccessTokenFromCookie(String accessTokenValue, String refreshTokenValue) {

        List<Cookie> cookies = new LinkedList<>();
        cookies.add(new Cookie(OAuth2AccessToken.ACCESS_TOKEN, accessTokenValue));
        if (refreshTokenValue != null) cookies.add(new Cookie(OAuth2AccessToken.REFRESH_TOKEN, refreshTokenValue));

        ((MockHttpServletRequest) context.getRequest()).setCookies(cookies.toArray(new Cookie[0]));

        TokenStore tokenStore = context.getTokenStore();
        Mockito.when(tokenStore.readAccessToken(accessTokenValue)).thenReturn(new DefaultOAuth2AccessToken(accessTokenValue));
        Mockito.when(tokenStore.readRefreshToken(refreshTokenValue)).thenReturn(new DefaultOAuth2RefreshToken(refreshTokenValue));

        OAuth2AccessToken accessToken = context.getAccessToken();

        assertThat(accessToken.getValue()).isEqualTo(accessTokenValue);
        if (refreshTokenValue == null)
            assertThat(accessToken.getRefreshToken()).isNull();
        else
            assertThat(accessToken.getRefreshToken().getValue()).isEqualTo(refreshTokenValue);

    }

    @Test
    public void getAccessTokenAndRefreshTokenFromCookie() {
        testGetAccessTokenFromCookie("access-token", "refresh-token");
    }

    @Test
    public void setPreservedState() throws Exception {

        String expectedJson = "{ \"key\": \"value\" }";
        String encodedState = Base64.getEncoder().encodeToString(expectedJson.getBytes(StandardCharsets.UTF_8));

        Mockito.when(context.getObjectMapper().writeValueAsString(any(HashMap.class))).thenReturn(expectedJson);

        context.setPreservedState("key", "value");

        Cookie stateCookie = ((MockHttpServletResponse) context.getResponse()).getCookie("state");
        assertThat(stateCookie).isNotNull();
        assertThat(stateCookie.getValue()).isEqualTo(encodedState);
        assertThat(stateCookie.getMaxAge()).isEqualTo(-1);

    }

    @Test
    public void removePreservedStateWithoutCookie() {
        context.removePreservedState("");
        assertThat(((MockHttpServletResponse) context.getResponse()).getCookie("state")).isNull();
    }

    @Test
    public void removeFromSinglePreservedState() throws Exception {
        HashMap<String, String> stateMap = new HashMap<>();
        stateMap.put("key", "value");
        removePreservedState("{ \"key\": \"value\" }", stateMap, cookie -> assertThat(cookie.getValue()).isEmpty());
    }

    private void removePreservedState(String stateJson, HashMap<String, String> stateMap, Consumer<Cookie> consumer) throws Exception {

        MockHttpServletRequest request = (MockHttpServletRequest) context.getRequest();
        String stateValue = Base64.getEncoder().encodeToString(stateJson.getBytes(StandardCharsets.UTF_8));
        request.setCookies(new Cookie("state", stateValue));

        ObjectMapper objectMapper = context.getObjectMapper();
        Mockito.when(objectMapper.readValue(stateJson, HashMap.class)).thenReturn(stateMap);

        Object result = context.removePreservedState("key");
        assertThat(result).isEqualTo("value");

        Cookie cookie = ((MockHttpServletResponse) context.getResponse()).getCookie("state");
        consumer.accept(cookie);

    }

    @Test
    public void removeFromMultiplePreservedState() throws Exception {

        String expectedJson = "{ \"keyTwo\": \"valueTwo\" }";
        Mockito.when(context.getObjectMapper().writeValueAsString(any(HashMap.class))).thenReturn(expectedJson);

        HashMap<String, String> stateMap = new HashMap<>();
        stateMap.put("key", "value");
        stateMap.put("keyTwo", "valueTwo");

        removePreservedState("{ \"key\": \"value\", \"keyTwo\": \"valueTwo\" }",
                stateMap,
                cookie -> assertThat(cookie.getValue()).isEqualTo(
                        Base64.getEncoder().encodeToString(expectedJson.getBytes(StandardCharsets.UTF_8))
                ));

    }

}