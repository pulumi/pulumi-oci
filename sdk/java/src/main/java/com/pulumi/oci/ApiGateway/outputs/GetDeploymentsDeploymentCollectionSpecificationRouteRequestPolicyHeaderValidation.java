// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeader;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidation {
    private List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeader> headers;
    /**
     * @return Validation behavior mode.
     * 
     */
    private String validationMode;

    private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidation() {}
    public List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeader> headers() {
        return this.headers;
    }
    /**
     * @return Validation behavior mode.
     * 
     */
    public String validationMode() {
        return this.validationMode;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeader> headers;
        private String validationMode;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.headers = defaults.headers;
    	      this.validationMode = defaults.validationMode;
        }

        @CustomType.Setter
        public Builder headers(List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeader> headers) {
            this.headers = Objects.requireNonNull(headers);
            return this;
        }
        public Builder headers(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeader... headers) {
            return headers(List.of(headers));
        }
        @CustomType.Setter
        public Builder validationMode(String validationMode) {
            this.validationMode = Objects.requireNonNull(validationMode);
            return this;
        }
        public GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidation build() {
            final var o = new GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidation();
            o.headers = headers;
            o.validationMode = validationMode;
            return o;
        }
    }
}