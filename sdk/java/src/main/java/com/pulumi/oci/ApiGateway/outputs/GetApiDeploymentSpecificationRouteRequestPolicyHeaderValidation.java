// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeader;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation {
    private List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeader> headers;
    /**
     * @return Validation behavior mode.
     * 
     */
    private String validationMode;

    private GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation() {}
    public List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeader> headers() {
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

    public static Builder builder(GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeader> headers;
        private String validationMode;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.headers = defaults.headers;
    	      this.validationMode = defaults.validationMode;
        }

        @CustomType.Setter
        public Builder headers(List<GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeader> headers) {
            if (headers == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation", "headers");
            }
            this.headers = headers;
            return this;
        }
        public Builder headers(GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeader... headers) {
            return headers(List.of(headers));
        }
        @CustomType.Setter
        public Builder validationMode(String validationMode) {
            if (validationMode == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation", "validationMode");
            }
            this.validationMode = validationMode;
            return this;
        }
        public GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation build() {
            final var _resultValue = new GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidation();
            _resultValue.headers = headers;
            _resultValue.validationMode = validationMode;
            return _resultValue;
        }
    }
}
