// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesAuthorizationArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesCorsArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesHeaderValidationsArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesResponseCacheLookupArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentSpecificationRouteRequestPoliciesArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteRequestPoliciesArgs Empty = new DeploymentSpecificationRouteRequestPoliciesArgs();

    /**
     * (Updatable) If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
     * 
     */
    @Import(name="authorization")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesAuthorizationArgs> authorization;

    /**
     * @return (Updatable) If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesAuthorizationArgs>> authorization() {
        return Optional.ofNullable(this.authorization);
    }

    /**
     * (Updatable) Validate the payload body of the incoming API requests on a specific route.
     * 
     */
    @Import(name="bodyValidation")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs> bodyValidation;

    /**
     * @return (Updatable) Validate the payload body of the incoming API requests on a specific route.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs>> bodyValidation() {
        return Optional.ofNullable(this.bodyValidation);
    }

    /**
     * (Updatable) Enable CORS (Cross-Origin-Resource-Sharing) request handling.
     * 
     */
    @Import(name="cors")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesCorsArgs> cors;

    /**
     * @return (Updatable) Enable CORS (Cross-Origin-Resource-Sharing) request handling.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesCorsArgs>> cors() {
        return Optional.ofNullable(this.cors);
    }

    /**
     * (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
     * 
     */
    @Import(name="headerTransformations")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsArgs> headerTransformations;

    /**
     * @return (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsArgs>> headerTransformations() {
        return Optional.ofNullable(this.headerTransformations);
    }

    /**
     * (Updatable) Validate the HTTP headers on the incoming API requests on a specific route.
     * 
     */
    @Import(name="headerValidations")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesHeaderValidationsArgs> headerValidations;

    /**
     * @return (Updatable) Validate the HTTP headers on the incoming API requests on a specific route.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesHeaderValidationsArgs>> headerValidations() {
        return Optional.ofNullable(this.headerValidations);
    }

    /**
     * (Updatable) A set of transformations to apply to query parameters that pass through the gateway.
     * 
     */
    @Import(name="queryParameterTransformations")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsArgs> queryParameterTransformations;

    /**
     * @return (Updatable) A set of transformations to apply to query parameters that pass through the gateway.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsArgs>> queryParameterTransformations() {
        return Optional.ofNullable(this.queryParameterTransformations);
    }

    /**
     * (Updatable) Validate the URL query parameters on the incoming API requests on a specific route.
     * 
     */
    @Import(name="queryParameterValidations")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsArgs> queryParameterValidations;

    /**
     * @return (Updatable) Validate the URL query parameters on the incoming API requests on a specific route.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsArgs>> queryParameterValidations() {
        return Optional.ofNullable(this.queryParameterValidations);
    }

    /**
     * (Updatable) Base policy for Response Cache lookup.
     * 
     */
    @Import(name="responseCacheLookup")
    private @Nullable Output<DeploymentSpecificationRouteRequestPoliciesResponseCacheLookupArgs> responseCacheLookup;

    /**
     * @return (Updatable) Base policy for Response Cache lookup.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteRequestPoliciesResponseCacheLookupArgs>> responseCacheLookup() {
        return Optional.ofNullable(this.responseCacheLookup);
    }

    private DeploymentSpecificationRouteRequestPoliciesArgs() {}

    private DeploymentSpecificationRouteRequestPoliciesArgs(DeploymentSpecificationRouteRequestPoliciesArgs $) {
        this.authorization = $.authorization;
        this.bodyValidation = $.bodyValidation;
        this.cors = $.cors;
        this.headerTransformations = $.headerTransformations;
        this.headerValidations = $.headerValidations;
        this.queryParameterTransformations = $.queryParameterTransformations;
        this.queryParameterValidations = $.queryParameterValidations;
        this.responseCacheLookup = $.responseCacheLookup;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteRequestPoliciesArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteRequestPoliciesArgs();
        }

        public Builder(DeploymentSpecificationRouteRequestPoliciesArgs defaults) {
            $ = new DeploymentSpecificationRouteRequestPoliciesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param authorization (Updatable) If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
         * 
         * @return builder
         * 
         */
        public Builder authorization(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesAuthorizationArgs> authorization) {
            $.authorization = authorization;
            return this;
        }

        /**
         * @param authorization (Updatable) If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
         * 
         * @return builder
         * 
         */
        public Builder authorization(DeploymentSpecificationRouteRequestPoliciesAuthorizationArgs authorization) {
            return authorization(Output.of(authorization));
        }

        /**
         * @param bodyValidation (Updatable) Validate the payload body of the incoming API requests on a specific route.
         * 
         * @return builder
         * 
         */
        public Builder bodyValidation(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs> bodyValidation) {
            $.bodyValidation = bodyValidation;
            return this;
        }

        /**
         * @param bodyValidation (Updatable) Validate the payload body of the incoming API requests on a specific route.
         * 
         * @return builder
         * 
         */
        public Builder bodyValidation(DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs bodyValidation) {
            return bodyValidation(Output.of(bodyValidation));
        }

        /**
         * @param cors (Updatable) Enable CORS (Cross-Origin-Resource-Sharing) request handling.
         * 
         * @return builder
         * 
         */
        public Builder cors(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesCorsArgs> cors) {
            $.cors = cors;
            return this;
        }

        /**
         * @param cors (Updatable) Enable CORS (Cross-Origin-Resource-Sharing) request handling.
         * 
         * @return builder
         * 
         */
        public Builder cors(DeploymentSpecificationRouteRequestPoliciesCorsArgs cors) {
            return cors(Output.of(cors));
        }

        /**
         * @param headerTransformations (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder headerTransformations(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsArgs> headerTransformations) {
            $.headerTransformations = headerTransformations;
            return this;
        }

        /**
         * @param headerTransformations (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder headerTransformations(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsArgs headerTransformations) {
            return headerTransformations(Output.of(headerTransformations));
        }

        /**
         * @param headerValidations (Updatable) Validate the HTTP headers on the incoming API requests on a specific route.
         * 
         * @return builder
         * 
         */
        public Builder headerValidations(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesHeaderValidationsArgs> headerValidations) {
            $.headerValidations = headerValidations;
            return this;
        }

        /**
         * @param headerValidations (Updatable) Validate the HTTP headers on the incoming API requests on a specific route.
         * 
         * @return builder
         * 
         */
        public Builder headerValidations(DeploymentSpecificationRouteRequestPoliciesHeaderValidationsArgs headerValidations) {
            return headerValidations(Output.of(headerValidations));
        }

        /**
         * @param queryParameterTransformations (Updatable) A set of transformations to apply to query parameters that pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder queryParameterTransformations(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsArgs> queryParameterTransformations) {
            $.queryParameterTransformations = queryParameterTransformations;
            return this;
        }

        /**
         * @param queryParameterTransformations (Updatable) A set of transformations to apply to query parameters that pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder queryParameterTransformations(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsArgs queryParameterTransformations) {
            return queryParameterTransformations(Output.of(queryParameterTransformations));
        }

        /**
         * @param queryParameterValidations (Updatable) Validate the URL query parameters on the incoming API requests on a specific route.
         * 
         * @return builder
         * 
         */
        public Builder queryParameterValidations(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsArgs> queryParameterValidations) {
            $.queryParameterValidations = queryParameterValidations;
            return this;
        }

        /**
         * @param queryParameterValidations (Updatable) Validate the URL query parameters on the incoming API requests on a specific route.
         * 
         * @return builder
         * 
         */
        public Builder queryParameterValidations(DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsArgs queryParameterValidations) {
            return queryParameterValidations(Output.of(queryParameterValidations));
        }

        /**
         * @param responseCacheLookup (Updatable) Base policy for Response Cache lookup.
         * 
         * @return builder
         * 
         */
        public Builder responseCacheLookup(@Nullable Output<DeploymentSpecificationRouteRequestPoliciesResponseCacheLookupArgs> responseCacheLookup) {
            $.responseCacheLookup = responseCacheLookup;
            return this;
        }

        /**
         * @param responseCacheLookup (Updatable) Base policy for Response Cache lookup.
         * 
         * @return builder
         * 
         */
        public Builder responseCacheLookup(DeploymentSpecificationRouteRequestPoliciesResponseCacheLookupArgs responseCacheLookup) {
            return responseCacheLookup(Output.of(responseCacheLookup));
        }

        public DeploymentSpecificationRouteRequestPoliciesArgs build() {
            return $;
        }
    }

}