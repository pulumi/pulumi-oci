// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformation;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteResponsePolicy {
    /**
     * @return A set of transformations to apply to HTTP headers that pass through the gateway.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformation> headerTransformations;
    /**
     * @return Base policy for how a response from a backend is cached in the Response Cache.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore> responseCacheStores;

    private GetApiDeploymentSpecificationRouteResponsePolicy() {}
    /**
     * @return A set of transformations to apply to HTTP headers that pass through the gateway.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformation> headerTransformations() {
        return this.headerTransformations;
    }
    /**
     * @return Base policy for how a response from a backend is cached in the Response Cache.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore> responseCacheStores() {
        return this.responseCacheStores;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteResponsePolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformation> headerTransformations;
        private List<GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore> responseCacheStores;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteResponsePolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.headerTransformations = defaults.headerTransformations;
    	      this.responseCacheStores = defaults.responseCacheStores;
        }

        @CustomType.Setter
        public Builder headerTransformations(List<GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformation> headerTransformations) {
            if (headerTransformations == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteResponsePolicy", "headerTransformations");
            }
            this.headerTransformations = headerTransformations;
            return this;
        }
        public Builder headerTransformations(GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformation... headerTransformations) {
            return headerTransformations(List.of(headerTransformations));
        }
        @CustomType.Setter
        public Builder responseCacheStores(List<GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore> responseCacheStores) {
            if (responseCacheStores == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteResponsePolicy", "responseCacheStores");
            }
            this.responseCacheStores = responseCacheStores;
            return this;
        }
        public Builder responseCacheStores(GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStore... responseCacheStores) {
            return responseCacheStores(List.of(responseCacheStores));
        }
        public GetApiDeploymentSpecificationRouteResponsePolicy build() {
            final var _resultValue = new GetApiDeploymentSpecificationRouteResponsePolicy();
            _resultValue.headerTransformations = headerTransformations;
            _resultValue.responseCacheStores = responseCacheStores;
            return _resultValue;
        }
    }
}
