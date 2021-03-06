// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BackendSetLbCookieSessionPersistenceConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final BackendSetLbCookieSessionPersistenceConfigurationArgs Empty = new BackendSetLbCookieSessionPersistenceConfigurationArgs();

    /**
     * (Updatable) The name of the cookie used to detect a session initiated by the backend server. Use &#39;*&#39; to specify that any cookie set by the backend causes the session to persist.  Example: `example_cookie`
     * 
     */
    @Import(name="cookieName")
    private @Nullable Output<String> cookieName;

    /**
     * @return (Updatable) The name of the cookie used to detect a session initiated by the backend server. Use &#39;*&#39; to specify that any cookie set by the backend causes the session to persist.  Example: `example_cookie`
     * 
     */
    public Optional<Output<String>> cookieName() {
        return Optional.ofNullable(this.cookieName);
    }

    /**
     * (Updatable) Whether the load balancer is prevented from directing traffic from a persistent session client to a different backend server if the original server is unavailable. Defaults to false.  Example: `false`
     * 
     */
    @Import(name="disableFallback")
    private @Nullable Output<Boolean> disableFallback;

    /**
     * @return (Updatable) Whether the load balancer is prevented from directing traffic from a persistent session client to a different backend server if the original server is unavailable. Defaults to false.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> disableFallback() {
        return Optional.ofNullable(this.disableFallback);
    }

    /**
     * (Updatable) The domain in which the cookie is valid. The `Set-cookie` header inserted by the load balancer contains a domain attribute with the specified value.
     * 
     */
    @Import(name="domain")
    private @Nullable Output<String> domain;

    /**
     * @return (Updatable) The domain in which the cookie is valid. The `Set-cookie` header inserted by the load balancer contains a domain attribute with the specified value.
     * 
     */
    public Optional<Output<String>> domain() {
        return Optional.ofNullable(this.domain);
    }

    /**
     * (Updatable) Whether the `Set-cookie` header should contain the `HttpOnly` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `HttpOnly` attribute, which limits the scope of the cookie to HTTP requests. This attribute directs the client or browser to omit the cookie when providing access to cookies through non-HTTP APIs. For example, it restricts the cookie from JavaScript channels.  Example: `true`
     * 
     */
    @Import(name="isHttpOnly")
    private @Nullable Output<Boolean> isHttpOnly;

    /**
     * @return (Updatable) Whether the `Set-cookie` header should contain the `HttpOnly` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `HttpOnly` attribute, which limits the scope of the cookie to HTTP requests. This attribute directs the client or browser to omit the cookie when providing access to cookies through non-HTTP APIs. For example, it restricts the cookie from JavaScript channels.  Example: `true`
     * 
     */
    public Optional<Output<Boolean>> isHttpOnly() {
        return Optional.ofNullable(this.isHttpOnly);
    }

    /**
     * (Updatable) Whether the `Set-cookie` header should contain the `Secure` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `Secure` attribute, which directs the client or browser to send the cookie only using a secure protocol.
     * 
     */
    @Import(name="isSecure")
    private @Nullable Output<Boolean> isSecure;

    /**
     * @return (Updatable) Whether the `Set-cookie` header should contain the `Secure` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `Secure` attribute, which directs the client or browser to send the cookie only using a secure protocol.
     * 
     */
    public Optional<Output<Boolean>> isSecure() {
        return Optional.ofNullable(this.isSecure);
    }

    /**
     * (Updatable) The amount of time the cookie remains valid. The `Set-cookie` header inserted by the load balancer contains a `Max-Age` attribute with the specified value.
     * 
     */
    @Import(name="maxAgeInSeconds")
    private @Nullable Output<Integer> maxAgeInSeconds;

    /**
     * @return (Updatable) The amount of time the cookie remains valid. The `Set-cookie` header inserted by the load balancer contains a `Max-Age` attribute with the specified value.
     * 
     */
    public Optional<Output<Integer>> maxAgeInSeconds() {
        return Optional.ofNullable(this.maxAgeInSeconds);
    }

    /**
     * (Updatable) The path in which the cookie is valid. The `Set-cookie header` inserted by the load balancer contains a `Path` attribute with the specified value.
     * 
     */
    @Import(name="path")
    private @Nullable Output<String> path;

    /**
     * @return (Updatable) The path in which the cookie is valid. The `Set-cookie header` inserted by the load balancer contains a `Path` attribute with the specified value.
     * 
     */
    public Optional<Output<String>> path() {
        return Optional.ofNullable(this.path);
    }

    private BackendSetLbCookieSessionPersistenceConfigurationArgs() {}

    private BackendSetLbCookieSessionPersistenceConfigurationArgs(BackendSetLbCookieSessionPersistenceConfigurationArgs $) {
        this.cookieName = $.cookieName;
        this.disableFallback = $.disableFallback;
        this.domain = $.domain;
        this.isHttpOnly = $.isHttpOnly;
        this.isSecure = $.isSecure;
        this.maxAgeInSeconds = $.maxAgeInSeconds;
        this.path = $.path;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BackendSetLbCookieSessionPersistenceConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BackendSetLbCookieSessionPersistenceConfigurationArgs $;

        public Builder() {
            $ = new BackendSetLbCookieSessionPersistenceConfigurationArgs();
        }

        public Builder(BackendSetLbCookieSessionPersistenceConfigurationArgs defaults) {
            $ = new BackendSetLbCookieSessionPersistenceConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param cookieName (Updatable) The name of the cookie used to detect a session initiated by the backend server. Use &#39;*&#39; to specify that any cookie set by the backend causes the session to persist.  Example: `example_cookie`
         * 
         * @return builder
         * 
         */
        public Builder cookieName(@Nullable Output<String> cookieName) {
            $.cookieName = cookieName;
            return this;
        }

        /**
         * @param cookieName (Updatable) The name of the cookie used to detect a session initiated by the backend server. Use &#39;*&#39; to specify that any cookie set by the backend causes the session to persist.  Example: `example_cookie`
         * 
         * @return builder
         * 
         */
        public Builder cookieName(String cookieName) {
            return cookieName(Output.of(cookieName));
        }

        /**
         * @param disableFallback (Updatable) Whether the load balancer is prevented from directing traffic from a persistent session client to a different backend server if the original server is unavailable. Defaults to false.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder disableFallback(@Nullable Output<Boolean> disableFallback) {
            $.disableFallback = disableFallback;
            return this;
        }

        /**
         * @param disableFallback (Updatable) Whether the load balancer is prevented from directing traffic from a persistent session client to a different backend server if the original server is unavailable. Defaults to false.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder disableFallback(Boolean disableFallback) {
            return disableFallback(Output.of(disableFallback));
        }

        /**
         * @param domain (Updatable) The domain in which the cookie is valid. The `Set-cookie` header inserted by the load balancer contains a domain attribute with the specified value.
         * 
         * @return builder
         * 
         */
        public Builder domain(@Nullable Output<String> domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param domain (Updatable) The domain in which the cookie is valid. The `Set-cookie` header inserted by the load balancer contains a domain attribute with the specified value.
         * 
         * @return builder
         * 
         */
        public Builder domain(String domain) {
            return domain(Output.of(domain));
        }

        /**
         * @param isHttpOnly (Updatable) Whether the `Set-cookie` header should contain the `HttpOnly` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `HttpOnly` attribute, which limits the scope of the cookie to HTTP requests. This attribute directs the client or browser to omit the cookie when providing access to cookies through non-HTTP APIs. For example, it restricts the cookie from JavaScript channels.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isHttpOnly(@Nullable Output<Boolean> isHttpOnly) {
            $.isHttpOnly = isHttpOnly;
            return this;
        }

        /**
         * @param isHttpOnly (Updatable) Whether the `Set-cookie` header should contain the `HttpOnly` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `HttpOnly` attribute, which limits the scope of the cookie to HTTP requests. This attribute directs the client or browser to omit the cookie when providing access to cookies through non-HTTP APIs. For example, it restricts the cookie from JavaScript channels.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isHttpOnly(Boolean isHttpOnly) {
            return isHttpOnly(Output.of(isHttpOnly));
        }

        /**
         * @param isSecure (Updatable) Whether the `Set-cookie` header should contain the `Secure` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `Secure` attribute, which directs the client or browser to send the cookie only using a secure protocol.
         * 
         * @return builder
         * 
         */
        public Builder isSecure(@Nullable Output<Boolean> isSecure) {
            $.isSecure = isSecure;
            return this;
        }

        /**
         * @param isSecure (Updatable) Whether the `Set-cookie` header should contain the `Secure` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `Secure` attribute, which directs the client or browser to send the cookie only using a secure protocol.
         * 
         * @return builder
         * 
         */
        public Builder isSecure(Boolean isSecure) {
            return isSecure(Output.of(isSecure));
        }

        /**
         * @param maxAgeInSeconds (Updatable) The amount of time the cookie remains valid. The `Set-cookie` header inserted by the load balancer contains a `Max-Age` attribute with the specified value.
         * 
         * @return builder
         * 
         */
        public Builder maxAgeInSeconds(@Nullable Output<Integer> maxAgeInSeconds) {
            $.maxAgeInSeconds = maxAgeInSeconds;
            return this;
        }

        /**
         * @param maxAgeInSeconds (Updatable) The amount of time the cookie remains valid. The `Set-cookie` header inserted by the load balancer contains a `Max-Age` attribute with the specified value.
         * 
         * @return builder
         * 
         */
        public Builder maxAgeInSeconds(Integer maxAgeInSeconds) {
            return maxAgeInSeconds(Output.of(maxAgeInSeconds));
        }

        /**
         * @param path (Updatable) The path in which the cookie is valid. The `Set-cookie header` inserted by the load balancer contains a `Path` attribute with the specified value.
         * 
         * @return builder
         * 
         */
        public Builder path(@Nullable Output<String> path) {
            $.path = path;
            return this;
        }

        /**
         * @param path (Updatable) The path in which the cookie is valid. The `Set-cookie header` inserted by the load balancer contains a `Path` attribute with the specified value.
         * 
         * @return builder
         * 
         */
        public Builder path(String path) {
            return path(Output.of(path));
        }

        public BackendSetLbCookieSessionPersistenceConfigurationArgs build() {
            return $;
        }
    }

}
