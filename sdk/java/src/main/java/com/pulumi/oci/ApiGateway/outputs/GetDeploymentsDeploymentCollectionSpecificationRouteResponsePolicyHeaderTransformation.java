// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationRenameHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationSetHeader;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformation {
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeader> filterHeaders;
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationRenameHeader> renameHeaders;
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationSetHeader> setHeaders;

    private GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformation() {}
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeader> filterHeaders() {
        return this.filterHeaders;
    }
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationRenameHeader> renameHeaders() {
        return this.renameHeaders;
    }
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationSetHeader> setHeaders() {
        return this.setHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeader> filterHeaders;
        private List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationRenameHeader> renameHeaders;
        private List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationSetHeader> setHeaders;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterHeaders = defaults.filterHeaders;
    	      this.renameHeaders = defaults.renameHeaders;
    	      this.setHeaders = defaults.setHeaders;
        }

        @CustomType.Setter
        public Builder filterHeaders(List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeader> filterHeaders) {
            this.filterHeaders = Objects.requireNonNull(filterHeaders);
            return this;
        }
        public Builder filterHeaders(GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeader... filterHeaders) {
            return filterHeaders(List.of(filterHeaders));
        }
        @CustomType.Setter
        public Builder renameHeaders(List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationRenameHeader> renameHeaders) {
            this.renameHeaders = Objects.requireNonNull(renameHeaders);
            return this;
        }
        public Builder renameHeaders(GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationRenameHeader... renameHeaders) {
            return renameHeaders(List.of(renameHeaders));
        }
        @CustomType.Setter
        public Builder setHeaders(List<GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationSetHeader> setHeaders) {
            this.setHeaders = Objects.requireNonNull(setHeaders);
            return this;
        }
        public Builder setHeaders(GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationSetHeader... setHeaders) {
            return setHeaders(List.of(setHeaders));
        }
        public GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformation build() {
            final var o = new GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformation();
            o.filterHeaders = filterHeaders;
            o.renameHeaders = renameHeaders;
            o.setHeaders = setHeaders;
            return o;
        }
    }
}