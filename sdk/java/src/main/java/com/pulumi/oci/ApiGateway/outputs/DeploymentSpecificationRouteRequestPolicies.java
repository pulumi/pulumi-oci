// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesAuthorization;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesBodyValidation;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesCors;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformations;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesHeaderValidations;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformations;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterValidations;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRouteRequestPoliciesResponseCacheLookup;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRouteRequestPolicies {
    /**
     * @return (Updatable) If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesAuthorization authorization;
    /**
     * @return (Updatable) Validate the payload body of the incoming API requests on a specific route.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesBodyValidation bodyValidation;
    /**
     * @return (Updatable) Enable CORS (Cross-Origin-Resource-Sharing) request handling.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesCors cors;
    /**
     * @return (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesHeaderTransformations headerTransformations;
    /**
     * @return (Updatable) Validate the HTTP headers on the incoming API requests on a specific route.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesHeaderValidations headerValidations;
    /**
     * @return (Updatable) A set of transformations to apply to query parameters that pass through the gateway.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformations queryParameterTransformations;
    /**
     * @return (Updatable) Validate the URL query parameters on the incoming API requests on a specific route.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesQueryParameterValidations queryParameterValidations;
    /**
     * @return (Updatable) Base policy for Response Cache lookup.
     * 
     */
    private @Nullable DeploymentSpecificationRouteRequestPoliciesResponseCacheLookup responseCacheLookup;

    private DeploymentSpecificationRouteRequestPolicies() {}
    /**
     * @return (Updatable) If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesAuthorization> authorization() {
        return Optional.ofNullable(this.authorization);
    }
    /**
     * @return (Updatable) Validate the payload body of the incoming API requests on a specific route.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesBodyValidation> bodyValidation() {
        return Optional.ofNullable(this.bodyValidation);
    }
    /**
     * @return (Updatable) Enable CORS (Cross-Origin-Resource-Sharing) request handling.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesCors> cors() {
        return Optional.ofNullable(this.cors);
    }
    /**
     * @return (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesHeaderTransformations> headerTransformations() {
        return Optional.ofNullable(this.headerTransformations);
    }
    /**
     * @return (Updatable) Validate the HTTP headers on the incoming API requests on a specific route.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesHeaderValidations> headerValidations() {
        return Optional.ofNullable(this.headerValidations);
    }
    /**
     * @return (Updatable) A set of transformations to apply to query parameters that pass through the gateway.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformations> queryParameterTransformations() {
        return Optional.ofNullable(this.queryParameterTransformations);
    }
    /**
     * @return (Updatable) Validate the URL query parameters on the incoming API requests on a specific route.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesQueryParameterValidations> queryParameterValidations() {
        return Optional.ofNullable(this.queryParameterValidations);
    }
    /**
     * @return (Updatable) Base policy for Response Cache lookup.
     * 
     */
    public Optional<DeploymentSpecificationRouteRequestPoliciesResponseCacheLookup> responseCacheLookup() {
        return Optional.ofNullable(this.responseCacheLookup);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPolicies defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable DeploymentSpecificationRouteRequestPoliciesAuthorization authorization;
        private @Nullable DeploymentSpecificationRouteRequestPoliciesBodyValidation bodyValidation;
        private @Nullable DeploymentSpecificationRouteRequestPoliciesCors cors;
        private @Nullable DeploymentSpecificationRouteRequestPoliciesHeaderTransformations headerTransformations;
        private @Nullable DeploymentSpecificationRouteRequestPoliciesHeaderValidations headerValidations;
        private @Nullable DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformations queryParameterTransformations;
        private @Nullable DeploymentSpecificationRouteRequestPoliciesQueryParameterValidations queryParameterValidations;
        private @Nullable DeploymentSpecificationRouteRequestPoliciesResponseCacheLookup responseCacheLookup;
        public Builder() {}
        public Builder(DeploymentSpecificationRouteRequestPolicies defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authorization = defaults.authorization;
    	      this.bodyValidation = defaults.bodyValidation;
    	      this.cors = defaults.cors;
    	      this.headerTransformations = defaults.headerTransformations;
    	      this.headerValidations = defaults.headerValidations;
    	      this.queryParameterTransformations = defaults.queryParameterTransformations;
    	      this.queryParameterValidations = defaults.queryParameterValidations;
    	      this.responseCacheLookup = defaults.responseCacheLookup;
        }

        @CustomType.Setter
        public Builder authorization(@Nullable DeploymentSpecificationRouteRequestPoliciesAuthorization authorization) {
            this.authorization = authorization;
            return this;
        }
        @CustomType.Setter
        public Builder bodyValidation(@Nullable DeploymentSpecificationRouteRequestPoliciesBodyValidation bodyValidation) {
            this.bodyValidation = bodyValidation;
            return this;
        }
        @CustomType.Setter
        public Builder cors(@Nullable DeploymentSpecificationRouteRequestPoliciesCors cors) {
            this.cors = cors;
            return this;
        }
        @CustomType.Setter
        public Builder headerTransformations(@Nullable DeploymentSpecificationRouteRequestPoliciesHeaderTransformations headerTransformations) {
            this.headerTransformations = headerTransformations;
            return this;
        }
        @CustomType.Setter
        public Builder headerValidations(@Nullable DeploymentSpecificationRouteRequestPoliciesHeaderValidations headerValidations) {
            this.headerValidations = headerValidations;
            return this;
        }
        @CustomType.Setter
        public Builder queryParameterTransformations(@Nullable DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformations queryParameterTransformations) {
            this.queryParameterTransformations = queryParameterTransformations;
            return this;
        }
        @CustomType.Setter
        public Builder queryParameterValidations(@Nullable DeploymentSpecificationRouteRequestPoliciesQueryParameterValidations queryParameterValidations) {
            this.queryParameterValidations = queryParameterValidations;
            return this;
        }
        @CustomType.Setter
        public Builder responseCacheLookup(@Nullable DeploymentSpecificationRouteRequestPoliciesResponseCacheLookup responseCacheLookup) {
            this.responseCacheLookup = responseCacheLookup;
            return this;
        }
        public DeploymentSpecificationRouteRequestPolicies build() {
            final var o = new DeploymentSpecificationRouteRequestPolicies();
            o.authorization = authorization;
            o.bodyValidation = bodyValidation;
            o.cors = cors;
            o.headerTransformations = headerTransformations;
            o.headerValidations = headerValidations;
            o.queryParameterTransformations = queryParameterTransformations;
            o.queryParameterValidations = queryParameterValidations;
            o.responseCacheLookup = responseCacheLookup;
            return o;
        }
    }
}