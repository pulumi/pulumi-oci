// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BackendSetLbCookieSessionPersistenceConfiguration {
    /**
     * @return (Updatable) The name of the cookie inserted by the load balancer. If this field is not configured, the cookie name defaults to &#34;X-Oracle-BMC-LBS-Route&#34;.  Example: `example_cookie`
     * 
     * **Notes:**
     * *  Ensure that the cookie name used at the backend application servers is different from the cookie name used at the load balancer. To minimize the chance of name collision, Oracle recommends that you use a prefix such as &#34;X-Oracle-OCI-&#34; for this field.
     * *  If a backend server and the load balancer both insert cookies with the same name, the client or browser behavior can vary depending on the domain and path values associated with the cookie. If the name, domain, and path values of the `Set-cookie` generated by a backend server and the `Set-cookie` generated by the load balancer are all the same, the client or browser treats them as one cookie and returns only one of the cookie values in subsequent requests. If both `Set-cookie` names are the same, but the domain and path names are different, the client or browser treats them as two different cookies.
     * 
     */
    private @Nullable String cookieName;
    /**
     * @return (Updatable) Whether the load balancer is prevented from directing traffic from a persistent session client to a different backend server if the original server is unavailable. Defaults to false.  Example: `false`
     * 
     */
    private @Nullable Boolean disableFallback;
    /**
     * @return (Updatable) The domain in which the cookie is valid. The `Set-cookie` header inserted by the load balancer contains a domain attribute with the specified value.
     * 
     * This attribute has no default value. If you do not specify a value, the load balancer does not insert the domain attribute into the `Set-cookie` header.
     * 
     * **Notes:**
     * *  [RFC 6265 - HTTP State Management Mechanism](https://www.ietf.org/rfc/rfc6265.txt) describes client and browser behavior when the domain attribute is present or not present in the `Set-cookie` header.
     * 
     * If the value of the `Domain` attribute is `example.com` in the `Set-cookie` header, the client includes the same cookie in the `Cookie` header when making HTTP requests to `example.com`, `www.example.com`, and `www.abc.example.com`. If the `Domain` attribute is not present, the client returns the cookie only for the domain to which the original request was made.
     * *  Ensure that this attribute specifies the correct domain value. If the `Domain` attribute in the `Set-cookie` header does not include the domain to which the original request was made, the client or browser might reject the cookie. As specified in RFC 6265, the client accepts a cookie with the `Domain` attribute value `example.com` or `www.example.com` sent from `www.example.com`. It does not accept a cookie with the `Domain` attribute `abc.example.com` or `www.abc.example.com` sent from `www.example.com`.
     * 
     * Example: `example.com`
     * 
     */
    private @Nullable String domain;
    /**
     * @return (Updatable) Whether the `Set-cookie` header should contain the `HttpOnly` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `HttpOnly` attribute, which limits the scope of the cookie to HTTP requests. This attribute directs the client or browser to omit the cookie when providing access to cookies through non-HTTP APIs. For example, it restricts the cookie from JavaScript channels.  Example: `true`
     * 
     */
    private @Nullable Boolean isHttpOnly;
    /**
     * @return (Updatable) Whether the `Set-cookie` header should contain the `Secure` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `Secure` attribute, which directs the client or browser to send the cookie only using a secure protocol.
     * 
     * **Note:** If you set this field to `true`, you cannot associate the corresponding backend set with an HTTP listener.
     * 
     * Example: `true`
     * 
     */
    private @Nullable Boolean isSecure;
    /**
     * @return (Updatable) The amount of time the cookie remains valid. The `Set-cookie` header inserted by the load balancer contains a `Max-Age` attribute with the specified value.
     * 
     * The specified value must be at least one second. There is no default value for this attribute. If you do not specify a value, the load balancer does not include the `Max-Age` attribute in the `Set-cookie` header. In most cases, the client or browser retains the cookie until the current session ends, as defined by the client.
     * 
     * Example: `3600`
     * 
     */
    private @Nullable Integer maxAgeInSeconds;
    /**
     * @return (Updatable) The path in which the cookie is valid. The `Set-cookie header` inserted by the load balancer contains a `Path` attribute with the specified value.
     * 
     * Clients include the cookie in an HTTP request only if the path portion of the request-uri matches, or is a subdirectory of, the cookie&#39;s `Path` attribute.
     * 
     * The default value is `/`.
     * 
     * Example: `/example`
     * 
     */
    private @Nullable String path;

    private BackendSetLbCookieSessionPersistenceConfiguration() {}
    /**
     * @return (Updatable) The name of the cookie inserted by the load balancer. If this field is not configured, the cookie name defaults to &#34;X-Oracle-BMC-LBS-Route&#34;.  Example: `example_cookie`
     * 
     * **Notes:**
     * *  Ensure that the cookie name used at the backend application servers is different from the cookie name used at the load balancer. To minimize the chance of name collision, Oracle recommends that you use a prefix such as &#34;X-Oracle-OCI-&#34; for this field.
     * *  If a backend server and the load balancer both insert cookies with the same name, the client or browser behavior can vary depending on the domain and path values associated with the cookie. If the name, domain, and path values of the `Set-cookie` generated by a backend server and the `Set-cookie` generated by the load balancer are all the same, the client or browser treats them as one cookie and returns only one of the cookie values in subsequent requests. If both `Set-cookie` names are the same, but the domain and path names are different, the client or browser treats them as two different cookies.
     * 
     */
    public Optional<String> cookieName() {
        return Optional.ofNullable(this.cookieName);
    }
    /**
     * @return (Updatable) Whether the load balancer is prevented from directing traffic from a persistent session client to a different backend server if the original server is unavailable. Defaults to false.  Example: `false`
     * 
     */
    public Optional<Boolean> disableFallback() {
        return Optional.ofNullable(this.disableFallback);
    }
    /**
     * @return (Updatable) The domain in which the cookie is valid. The `Set-cookie` header inserted by the load balancer contains a domain attribute with the specified value.
     * 
     * This attribute has no default value. If you do not specify a value, the load balancer does not insert the domain attribute into the `Set-cookie` header.
     * 
     * **Notes:**
     * *  [RFC 6265 - HTTP State Management Mechanism](https://www.ietf.org/rfc/rfc6265.txt) describes client and browser behavior when the domain attribute is present or not present in the `Set-cookie` header.
     * 
     * If the value of the `Domain` attribute is `example.com` in the `Set-cookie` header, the client includes the same cookie in the `Cookie` header when making HTTP requests to `example.com`, `www.example.com`, and `www.abc.example.com`. If the `Domain` attribute is not present, the client returns the cookie only for the domain to which the original request was made.
     * *  Ensure that this attribute specifies the correct domain value. If the `Domain` attribute in the `Set-cookie` header does not include the domain to which the original request was made, the client or browser might reject the cookie. As specified in RFC 6265, the client accepts a cookie with the `Domain` attribute value `example.com` or `www.example.com` sent from `www.example.com`. It does not accept a cookie with the `Domain` attribute `abc.example.com` or `www.abc.example.com` sent from `www.example.com`.
     * 
     * Example: `example.com`
     * 
     */
    public Optional<String> domain() {
        return Optional.ofNullable(this.domain);
    }
    /**
     * @return (Updatable) Whether the `Set-cookie` header should contain the `HttpOnly` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `HttpOnly` attribute, which limits the scope of the cookie to HTTP requests. This attribute directs the client or browser to omit the cookie when providing access to cookies through non-HTTP APIs. For example, it restricts the cookie from JavaScript channels.  Example: `true`
     * 
     */
    public Optional<Boolean> isHttpOnly() {
        return Optional.ofNullable(this.isHttpOnly);
    }
    /**
     * @return (Updatable) Whether the `Set-cookie` header should contain the `Secure` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `Secure` attribute, which directs the client or browser to send the cookie only using a secure protocol.
     * 
     * **Note:** If you set this field to `true`, you cannot associate the corresponding backend set with an HTTP listener.
     * 
     * Example: `true`
     * 
     */
    public Optional<Boolean> isSecure() {
        return Optional.ofNullable(this.isSecure);
    }
    /**
     * @return (Updatable) The amount of time the cookie remains valid. The `Set-cookie` header inserted by the load balancer contains a `Max-Age` attribute with the specified value.
     * 
     * The specified value must be at least one second. There is no default value for this attribute. If you do not specify a value, the load balancer does not include the `Max-Age` attribute in the `Set-cookie` header. In most cases, the client or browser retains the cookie until the current session ends, as defined by the client.
     * 
     * Example: `3600`
     * 
     */
    public Optional<Integer> maxAgeInSeconds() {
        return Optional.ofNullable(this.maxAgeInSeconds);
    }
    /**
     * @return (Updatable) The path in which the cookie is valid. The `Set-cookie header` inserted by the load balancer contains a `Path` attribute with the specified value.
     * 
     * Clients include the cookie in an HTTP request only if the path portion of the request-uri matches, or is a subdirectory of, the cookie&#39;s `Path` attribute.
     * 
     * The default value is `/`.
     * 
     * Example: `/example`
     * 
     */
    public Optional<String> path() {
        return Optional.ofNullable(this.path);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BackendSetLbCookieSessionPersistenceConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String cookieName;
        private @Nullable Boolean disableFallback;
        private @Nullable String domain;
        private @Nullable Boolean isHttpOnly;
        private @Nullable Boolean isSecure;
        private @Nullable Integer maxAgeInSeconds;
        private @Nullable String path;
        public Builder() {}
        public Builder(BackendSetLbCookieSessionPersistenceConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cookieName = defaults.cookieName;
    	      this.disableFallback = defaults.disableFallback;
    	      this.domain = defaults.domain;
    	      this.isHttpOnly = defaults.isHttpOnly;
    	      this.isSecure = defaults.isSecure;
    	      this.maxAgeInSeconds = defaults.maxAgeInSeconds;
    	      this.path = defaults.path;
        }

        @CustomType.Setter
        public Builder cookieName(@Nullable String cookieName) {

            this.cookieName = cookieName;
            return this;
        }
        @CustomType.Setter
        public Builder disableFallback(@Nullable Boolean disableFallback) {

            this.disableFallback = disableFallback;
            return this;
        }
        @CustomType.Setter
        public Builder domain(@Nullable String domain) {

            this.domain = domain;
            return this;
        }
        @CustomType.Setter
        public Builder isHttpOnly(@Nullable Boolean isHttpOnly) {

            this.isHttpOnly = isHttpOnly;
            return this;
        }
        @CustomType.Setter
        public Builder isSecure(@Nullable Boolean isSecure) {

            this.isSecure = isSecure;
            return this;
        }
        @CustomType.Setter
        public Builder maxAgeInSeconds(@Nullable Integer maxAgeInSeconds) {

            this.maxAgeInSeconds = maxAgeInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder path(@Nullable String path) {

            this.path = path;
            return this;
        }
        public BackendSetLbCookieSessionPersistenceConfiguration build() {
            final var _resultValue = new BackendSetLbCookieSessionPersistenceConfiguration();
            _resultValue.cookieName = cookieName;
            _resultValue.disableFallback = disableFallback;
            _resultValue.domain = domain;
            _resultValue.isHttpOnly = isHttpOnly;
            _resultValue.isSecure = isSecure;
            _resultValue.maxAgeInSeconds = maxAgeInSeconds;
            _resultValue.path = path;
            return _resultValue;
        }
    }
}
