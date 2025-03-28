// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetClustersClusterOptionAdmissionControllerOption {
    /**
     * @return Whether or not to enable the Pod Security Policy admission controller.
     * 
     */
    private Boolean isPodSecurityPolicyEnabled;

    private GetClustersClusterOptionAdmissionControllerOption() {}
    /**
     * @return Whether or not to enable the Pod Security Policy admission controller.
     * 
     */
    public Boolean isPodSecurityPolicyEnabled() {
        return this.isPodSecurityPolicyEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClustersClusterOptionAdmissionControllerOption defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isPodSecurityPolicyEnabled;
        public Builder() {}
        public Builder(GetClustersClusterOptionAdmissionControllerOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isPodSecurityPolicyEnabled = defaults.isPodSecurityPolicyEnabled;
        }

        @CustomType.Setter
        public Builder isPodSecurityPolicyEnabled(Boolean isPodSecurityPolicyEnabled) {
            if (isPodSecurityPolicyEnabled == null) {
              throw new MissingRequiredPropertyException("GetClustersClusterOptionAdmissionControllerOption", "isPodSecurityPolicyEnabled");
            }
            this.isPodSecurityPolicyEnabled = isPodSecurityPolicyEnabled;
            return this;
        }
        public GetClustersClusterOptionAdmissionControllerOption build() {
            final var _resultValue = new GetClustersClusterOptionAdmissionControllerOption();
            _resultValue.isPodSecurityPolicyEnabled = isPodSecurityPolicyEnabled;
            return _resultValue;
        }
    }
}
