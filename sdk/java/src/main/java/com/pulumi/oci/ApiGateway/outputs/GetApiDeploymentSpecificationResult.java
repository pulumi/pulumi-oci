// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationLoggingPolicy;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRequestPolicy;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRoute;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationResult {
    private String apiId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
     * 
     */
    private List<GetApiDeploymentSpecificationLoggingPolicy> loggingPolicies;
    /**
     * @return Behavior applied to any requests received by the API on this route.
     * 
     */
    private List<GetApiDeploymentSpecificationRequestPolicy> requestPolicies;
    /**
     * @return A list of routes that this API exposes.
     * 
     */
    private List<GetApiDeploymentSpecificationRoute> routes;

    private GetApiDeploymentSpecificationResult() {}
    public String apiId() {
        return this.apiId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
     * 
     */
    public List<GetApiDeploymentSpecificationLoggingPolicy> loggingPolicies() {
        return this.loggingPolicies;
    }
    /**
     * @return Behavior applied to any requests received by the API on this route.
     * 
     */
    public List<GetApiDeploymentSpecificationRequestPolicy> requestPolicies() {
        return this.requestPolicies;
    }
    /**
     * @return A list of routes that this API exposes.
     * 
     */
    public List<GetApiDeploymentSpecificationRoute> routes() {
        return this.routes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apiId;
        private String id;
        private List<GetApiDeploymentSpecificationLoggingPolicy> loggingPolicies;
        private List<GetApiDeploymentSpecificationRequestPolicy> requestPolicies;
        private List<GetApiDeploymentSpecificationRoute> routes;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apiId = defaults.apiId;
    	      this.id = defaults.id;
    	      this.loggingPolicies = defaults.loggingPolicies;
    	      this.requestPolicies = defaults.requestPolicies;
    	      this.routes = defaults.routes;
        }

        @CustomType.Setter
        public Builder apiId(String apiId) {
            if (apiId == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationResult", "apiId");
            }
            this.apiId = apiId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder loggingPolicies(List<GetApiDeploymentSpecificationLoggingPolicy> loggingPolicies) {
            if (loggingPolicies == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationResult", "loggingPolicies");
            }
            this.loggingPolicies = loggingPolicies;
            return this;
        }
        public Builder loggingPolicies(GetApiDeploymentSpecificationLoggingPolicy... loggingPolicies) {
            return loggingPolicies(List.of(loggingPolicies));
        }
        @CustomType.Setter
        public Builder requestPolicies(List<GetApiDeploymentSpecificationRequestPolicy> requestPolicies) {
            if (requestPolicies == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationResult", "requestPolicies");
            }
            this.requestPolicies = requestPolicies;
            return this;
        }
        public Builder requestPolicies(GetApiDeploymentSpecificationRequestPolicy... requestPolicies) {
            return requestPolicies(List.of(requestPolicies));
        }
        @CustomType.Setter
        public Builder routes(List<GetApiDeploymentSpecificationRoute> routes) {
            if (routes == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationResult", "routes");
            }
            this.routes = routes;
            return this;
        }
        public Builder routes(GetApiDeploymentSpecificationRoute... routes) {
            return routes(List.of(routes));
        }
        public GetApiDeploymentSpecificationResult build() {
            final var _resultValue = new GetApiDeploymentSpecificationResult();
            _resultValue.apiId = apiId;
            _resultValue.id = id;
            _resultValue.loggingPolicies = loggingPolicies;
            _resultValue.requestPolicies = requestPolicies;
            _resultValue.routes = routes;
            return _resultValue;
        }
    }
}
