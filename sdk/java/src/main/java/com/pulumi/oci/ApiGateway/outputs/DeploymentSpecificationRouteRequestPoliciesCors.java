// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRouteRequestPoliciesCors {
    /**
     * @return (Updatable) The list of headers that will be allowed from the client via the Access-Control-Allow-Headers header. &#39;*&#39; will allow all headers.
     * 
     */
    private @Nullable List<String> allowedHeaders;
    /**
     * @return (Updatable) The list of allowed HTTP methods that will be returned for the preflight OPTIONS request in the Access-Control-Allow-Methods header. &#39;*&#39; will allow all methods.
     * 
     */
    private @Nullable List<String> allowedMethods;
    /**
     * @return (Updatable) The list of allowed origins that the CORS handler will use to respond to CORS requests. The gateway will send the Access-Control-Allow-Origin header with the best origin match for the circumstances. &#39;*&#39; will match any origins, and &#39;null&#39; will match queries from &#39;file:&#39; origins. All other origins must be qualified with the scheme, full hostname, and port if necessary.
     * 
     */
    private List<String> allowedOrigins;
    /**
     * @return (Updatable) The list of headers that the client will be allowed to see from the response as indicated by the Access-Control-Expose-Headers header. &#39;*&#39; will expose all headers.
     * 
     */
    private @Nullable List<String> exposedHeaders;
    /**
     * @return (Updatable) Whether to send the Access-Control-Allow-Credentials header to allow CORS requests with cookies.
     * 
     */
    private @Nullable Boolean isAllowCredentialsEnabled;
    /**
     * @return (Updatable) The time in seconds for the client to cache preflight responses. This is sent as the Access-Control-Max-Age if greater than 0.
     * 
     */
    private @Nullable Integer maxAgeInSeconds;

    private DeploymentSpecificationRouteRequestPoliciesCors() {}
    /**
     * @return (Updatable) The list of headers that will be allowed from the client via the Access-Control-Allow-Headers header. &#39;*&#39; will allow all headers.
     * 
     */
    public List<String> allowedHeaders() {
        return this.allowedHeaders == null ? List.of() : this.allowedHeaders;
    }
    /**
     * @return (Updatable) The list of allowed HTTP methods that will be returned for the preflight OPTIONS request in the Access-Control-Allow-Methods header. &#39;*&#39; will allow all methods.
     * 
     */
    public List<String> allowedMethods() {
        return this.allowedMethods == null ? List.of() : this.allowedMethods;
    }
    /**
     * @return (Updatable) The list of allowed origins that the CORS handler will use to respond to CORS requests. The gateway will send the Access-Control-Allow-Origin header with the best origin match for the circumstances. &#39;*&#39; will match any origins, and &#39;null&#39; will match queries from &#39;file:&#39; origins. All other origins must be qualified with the scheme, full hostname, and port if necessary.
     * 
     */
    public List<String> allowedOrigins() {
        return this.allowedOrigins;
    }
    /**
     * @return (Updatable) The list of headers that the client will be allowed to see from the response as indicated by the Access-Control-Expose-Headers header. &#39;*&#39; will expose all headers.
     * 
     */
    public List<String> exposedHeaders() {
        return this.exposedHeaders == null ? List.of() : this.exposedHeaders;
    }
    /**
     * @return (Updatable) Whether to send the Access-Control-Allow-Credentials header to allow CORS requests with cookies.
     * 
     */
    public Optional<Boolean> isAllowCredentialsEnabled() {
        return Optional.ofNullable(this.isAllowCredentialsEnabled);
    }
    /**
     * @return (Updatable) The time in seconds for the client to cache preflight responses. This is sent as the Access-Control-Max-Age if greater than 0.
     * 
     */
    public Optional<Integer> maxAgeInSeconds() {
        return Optional.ofNullable(this.maxAgeInSeconds);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesCors defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> allowedHeaders;
        private @Nullable List<String> allowedMethods;
        private List<String> allowedOrigins;
        private @Nullable List<String> exposedHeaders;
        private @Nullable Boolean isAllowCredentialsEnabled;
        private @Nullable Integer maxAgeInSeconds;
        public Builder() {}
        public Builder(DeploymentSpecificationRouteRequestPoliciesCors defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowedHeaders = defaults.allowedHeaders;
    	      this.allowedMethods = defaults.allowedMethods;
    	      this.allowedOrigins = defaults.allowedOrigins;
    	      this.exposedHeaders = defaults.exposedHeaders;
    	      this.isAllowCredentialsEnabled = defaults.isAllowCredentialsEnabled;
    	      this.maxAgeInSeconds = defaults.maxAgeInSeconds;
        }

        @CustomType.Setter
        public Builder allowedHeaders(@Nullable List<String> allowedHeaders) {
            this.allowedHeaders = allowedHeaders;
            return this;
        }
        public Builder allowedHeaders(String... allowedHeaders) {
            return allowedHeaders(List.of(allowedHeaders));
        }
        @CustomType.Setter
        public Builder allowedMethods(@Nullable List<String> allowedMethods) {
            this.allowedMethods = allowedMethods;
            return this;
        }
        public Builder allowedMethods(String... allowedMethods) {
            return allowedMethods(List.of(allowedMethods));
        }
        @CustomType.Setter
        public Builder allowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = Objects.requireNonNull(allowedOrigins);
            return this;
        }
        public Builder allowedOrigins(String... allowedOrigins) {
            return allowedOrigins(List.of(allowedOrigins));
        }
        @CustomType.Setter
        public Builder exposedHeaders(@Nullable List<String> exposedHeaders) {
            this.exposedHeaders = exposedHeaders;
            return this;
        }
        public Builder exposedHeaders(String... exposedHeaders) {
            return exposedHeaders(List.of(exposedHeaders));
        }
        @CustomType.Setter
        public Builder isAllowCredentialsEnabled(@Nullable Boolean isAllowCredentialsEnabled) {
            this.isAllowCredentialsEnabled = isAllowCredentialsEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder maxAgeInSeconds(@Nullable Integer maxAgeInSeconds) {
            this.maxAgeInSeconds = maxAgeInSeconds;
            return this;
        }
        public DeploymentSpecificationRouteRequestPoliciesCors build() {
            final var o = new DeploymentSpecificationRouteRequestPoliciesCors();
            o.allowedHeaders = allowedHeaders;
            o.allowedMethods = allowedMethods;
            o.allowedOrigins = allowedOrigins;
            o.exposedHeaders = exposedHeaders;
            o.isAllowCredentialsEnabled = isAllowCredentialsEnabled;
            o.maxAgeInSeconds = maxAgeInSeconds;
            return o;
        }
    }
}