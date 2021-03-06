// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRouteRequestPolicyHeaderTransformation {
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private final List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders;
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    private final List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders;
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    private final List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders;

    @CustomType.Constructor
    private GetDeploymentSpecificationRouteRequestPolicyHeaderTransformation(
        @CustomType.Parameter("filterHeaders") List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders,
        @CustomType.Parameter("renameHeaders") List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders,
        @CustomType.Parameter("setHeaders") List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders) {
        this.filterHeaders = filterHeaders;
        this.renameHeaders = renameHeaders;
        this.setHeaders = setHeaders;
    }

    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders() {
        return this.filterHeaders;
    }
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders() {
        return this.renameHeaders;
    }
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders() {
        return this.setHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRouteRequestPolicyHeaderTransformation defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders;
        private List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders;
        private List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeploymentSpecificationRouteRequestPolicyHeaderTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterHeaders = defaults.filterHeaders;
    	      this.renameHeaders = defaults.renameHeaders;
    	      this.setHeaders = defaults.setHeaders;
        }

        public Builder filterHeaders(List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders) {
            this.filterHeaders = Objects.requireNonNull(filterHeaders);
            return this;
        }
        public Builder filterHeaders(GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader... filterHeaders) {
            return filterHeaders(List.of(filterHeaders));
        }
        public Builder renameHeaders(List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders) {
            this.renameHeaders = Objects.requireNonNull(renameHeaders);
            return this;
        }
        public Builder renameHeaders(GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader... renameHeaders) {
            return renameHeaders(List.of(renameHeaders));
        }
        public Builder setHeaders(List<GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders) {
            this.setHeaders = Objects.requireNonNull(setHeaders);
            return this;
        }
        public Builder setHeaders(GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader... setHeaders) {
            return setHeaders(List.of(setHeaders));
        }        public GetDeploymentSpecificationRouteRequestPolicyHeaderTransformation build() {
            return new GetDeploymentSpecificationRouteRequestPolicyHeaderTransformation(filterHeaders, renameHeaders, setHeaders);
        }
    }
}
