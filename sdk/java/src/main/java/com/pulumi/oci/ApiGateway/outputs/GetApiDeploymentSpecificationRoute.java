// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteBackend;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteLoggingPolicy;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicy;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteResponsePolicy;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRoute {
    /**
     * @return The backend to forward requests to.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteBackend> backends;
    /**
     * @return Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteLoggingPolicy> loggingPolicies;
    /**
     * @return A list of allowed methods on this route.
     * 
     */
    private List<String> methods;
    /**
     * @return A URL path pattern that must be matched on this route. The path pattern may contain a subset of RFC 6570 identifiers to allow wildcard and parameterized matching.
     * 
     */
    private String path;
    /**
     * @return Behavior applied to any requests received by the API on this route.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteRequestPolicy> requestPolicies;
    /**
     * @return Behavior applied to any responses sent by the API for requests on this route.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteResponsePolicy> responsePolicies;

    private GetApiDeploymentSpecificationRoute() {}
    /**
     * @return The backend to forward requests to.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteBackend> backends() {
        return this.backends;
    }
    /**
     * @return Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteLoggingPolicy> loggingPolicies() {
        return this.loggingPolicies;
    }
    /**
     * @return A list of allowed methods on this route.
     * 
     */
    public List<String> methods() {
        return this.methods;
    }
    /**
     * @return A URL path pattern that must be matched on this route. The path pattern may contain a subset of RFC 6570 identifiers to allow wildcard and parameterized matching.
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return Behavior applied to any requests received by the API on this route.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicy> requestPolicies() {
        return this.requestPolicies;
    }
    /**
     * @return Behavior applied to any responses sent by the API for requests on this route.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteResponsePolicy> responsePolicies() {
        return this.responsePolicies;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRoute defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteBackend> backends;
        private List<GetApiDeploymentSpecificationRouteLoggingPolicy> loggingPolicies;
        private List<String> methods;
        private String path;
        private List<GetApiDeploymentSpecificationRouteRequestPolicy> requestPolicies;
        private List<GetApiDeploymentSpecificationRouteResponsePolicy> responsePolicies;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRoute defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backends = defaults.backends;
    	      this.loggingPolicies = defaults.loggingPolicies;
    	      this.methods = defaults.methods;
    	      this.path = defaults.path;
    	      this.requestPolicies = defaults.requestPolicies;
    	      this.responsePolicies = defaults.responsePolicies;
        }

        @CustomType.Setter
        public Builder backends(List<GetApiDeploymentSpecificationRouteBackend> backends) {
            if (backends == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRoute", "backends");
            }
            this.backends = backends;
            return this;
        }
        public Builder backends(GetApiDeploymentSpecificationRouteBackend... backends) {
            return backends(List.of(backends));
        }
        @CustomType.Setter
        public Builder loggingPolicies(List<GetApiDeploymentSpecificationRouteLoggingPolicy> loggingPolicies) {
            if (loggingPolicies == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRoute", "loggingPolicies");
            }
            this.loggingPolicies = loggingPolicies;
            return this;
        }
        public Builder loggingPolicies(GetApiDeploymentSpecificationRouteLoggingPolicy... loggingPolicies) {
            return loggingPolicies(List.of(loggingPolicies));
        }
        @CustomType.Setter
        public Builder methods(List<String> methods) {
            if (methods == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRoute", "methods");
            }
            this.methods = methods;
            return this;
        }
        public Builder methods(String... methods) {
            return methods(List.of(methods));
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRoute", "path");
            }
            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder requestPolicies(List<GetApiDeploymentSpecificationRouteRequestPolicy> requestPolicies) {
            if (requestPolicies == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRoute", "requestPolicies");
            }
            this.requestPolicies = requestPolicies;
            return this;
        }
        public Builder requestPolicies(GetApiDeploymentSpecificationRouteRequestPolicy... requestPolicies) {
            return requestPolicies(List.of(requestPolicies));
        }
        @CustomType.Setter
        public Builder responsePolicies(List<GetApiDeploymentSpecificationRouteResponsePolicy> responsePolicies) {
            if (responsePolicies == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRoute", "responsePolicies");
            }
            this.responsePolicies = responsePolicies;
            return this;
        }
        public Builder responsePolicies(GetApiDeploymentSpecificationRouteResponsePolicy... responsePolicies) {
            return responsePolicies(List.of(responsePolicies));
        }
        public GetApiDeploymentSpecificationRoute build() {
            final var _resultValue = new GetApiDeploymentSpecificationRoute();
            _resultValue.backends = backends;
            _resultValue.loggingPolicies = loggingPolicies;
            _resultValue.methods = methods;
            _resultValue.path = path;
            _resultValue.requestPolicies = requestPolicies;
            _resultValue.responsePolicies = responsePolicies;
            return _resultValue;
        }
    }
}
