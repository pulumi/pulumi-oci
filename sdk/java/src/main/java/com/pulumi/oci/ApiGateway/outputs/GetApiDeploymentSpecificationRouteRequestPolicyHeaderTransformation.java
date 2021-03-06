// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformation {
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private final List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders;
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    private final List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders;
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    private final List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders;

    @CustomType.Constructor
    private GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformation(
        @CustomType.Parameter("filterHeaders") List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders,
        @CustomType.Parameter("renameHeaders") List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders,
        @CustomType.Parameter("setHeaders") List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders) {
        this.filterHeaders = filterHeaders;
        this.renameHeaders = renameHeaders;
        this.setHeaders = setHeaders;
    }

    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders() {
        return this.filterHeaders;
    }
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders() {
        return this.renameHeaders;
    }
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders() {
        return this.setHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformation defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders;
        private List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders;
        private List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders;

        public Builder() {
    	      // Empty
        }

        public Builder(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterHeaders = defaults.filterHeaders;
    	      this.renameHeaders = defaults.renameHeaders;
    	      this.setHeaders = defaults.setHeaders;
        }

        public Builder filterHeaders(List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader> filterHeaders) {
            this.filterHeaders = Objects.requireNonNull(filterHeaders);
            return this;
        }
        public Builder filterHeaders(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationFilterHeader... filterHeaders) {
            return filterHeaders(List.of(filterHeaders));
        }
        public Builder renameHeaders(List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader> renameHeaders) {
            this.renameHeaders = Objects.requireNonNull(renameHeaders);
            return this;
        }
        public Builder renameHeaders(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationRenameHeader... renameHeaders) {
            return renameHeaders(List.of(renameHeaders));
        }
        public Builder setHeaders(List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader> setHeaders) {
            this.setHeaders = Objects.requireNonNull(setHeaders);
            return this;
        }
        public Builder setHeaders(GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformationSetHeader... setHeaders) {
            return setHeaders(List.of(setHeaders));
        }        public GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformation build() {
            return new GetApiDeploymentSpecificationRouteRequestPolicyHeaderTransformation(filterHeaders, renameHeaders, setHeaders);
        }
    }
}
