// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationLoggingPolicy;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicy;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRoute;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecification {
    /**
     * @return Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationLoggingPolicy> loggingPolicies;
    /**
     * @return Behavior applied to any requests received by the API on this route.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicy> requestPolicies;
    /**
     * @return A list of routes that this API exposes.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRoute> routes;

    private GetDeploymentsDeploymentCollectionSpecification() {}
    /**
     * @return Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationLoggingPolicy> loggingPolicies() {
        return this.loggingPolicies;
    }
    /**
     * @return Behavior applied to any requests received by the API on this route.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicy> requestPolicies() {
        return this.requestPolicies;
    }
    /**
     * @return A list of routes that this API exposes.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRoute> routes() {
        return this.routes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecification defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentsDeploymentCollectionSpecificationLoggingPolicy> loggingPolicies;
        private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicy> requestPolicies;
        private List<GetDeploymentsDeploymentCollectionSpecificationRoute> routes;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionSpecification defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.loggingPolicies = defaults.loggingPolicies;
    	      this.requestPolicies = defaults.requestPolicies;
    	      this.routes = defaults.routes;
        }

        @CustomType.Setter
        public Builder loggingPolicies(List<GetDeploymentsDeploymentCollectionSpecificationLoggingPolicy> loggingPolicies) {
            this.loggingPolicies = Objects.requireNonNull(loggingPolicies);
            return this;
        }
        public Builder loggingPolicies(GetDeploymentsDeploymentCollectionSpecificationLoggingPolicy... loggingPolicies) {
            return loggingPolicies(List.of(loggingPolicies));
        }
        @CustomType.Setter
        public Builder requestPolicies(List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicy> requestPolicies) {
            this.requestPolicies = Objects.requireNonNull(requestPolicies);
            return this;
        }
        public Builder requestPolicies(GetDeploymentsDeploymentCollectionSpecificationRequestPolicy... requestPolicies) {
            return requestPolicies(List.of(requestPolicies));
        }
        @CustomType.Setter
        public Builder routes(List<GetDeploymentsDeploymentCollectionSpecificationRoute> routes) {
            this.routes = Objects.requireNonNull(routes);
            return this;
        }
        public Builder routes(GetDeploymentsDeploymentCollectionSpecificationRoute... routes) {
            return routes(List.of(routes));
        }
        public GetDeploymentsDeploymentCollectionSpecification build() {
            final var o = new GetDeploymentsDeploymentCollectionSpecification();
            o.loggingPolicies = loggingPolicies;
            o.requestPolicies = requestPolicies;
            o.routes = routes;
            return o;
        }
    }
}