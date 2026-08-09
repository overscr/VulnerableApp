package org.sasanlabs.configuration;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Sets a strict referrer policy on the password-reset page. The reset link embeds a
 * security-sensitive, single-use token as a query parameter; if the browser is allowed to send
 * the full URL as a Referer header to any third-party resource the page loads (images, fonts,
 * analytics, etc.), that token leaks to whoever operates the third-party origin and can be used
 * to hijack the reset before the legitimate user acts on it.
 *
 * <p>Fixed: this filter previously forced {@code Referrer-Policy: unsafe-url} for one specific
 * level to demonstrate that leak. It now always sets {@code no-referrer} on the reset page so no
 * outbound request from that page - regardless of level - ever carries the token in a Referer
 * header.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE - 100)
public class PasswordResetReferrerPolicyFilter extends OncePerRequestFilter {

    private static final String RESET_PAGE_PATH = "/password-reset/reset.html";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (isResetPage(request)) {
            response.setHeader("Referrer-Policy", "no-referrer");
        }
        filterChain.doFilter(request, response);
    }

    private boolean isResetPage(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        return requestUri != null && requestUri.endsWith(RESET_PAGE_PATH);
    }
}
