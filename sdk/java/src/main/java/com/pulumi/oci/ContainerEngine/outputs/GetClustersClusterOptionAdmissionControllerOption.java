// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetClustersClusterOptionAdmissionControllerOption {
    /**
     * @return Whether or not to enable the Pod Security Policy admission controller.
     * 
     */
    private final Boolean isPodSecurityPolicyEnabled;

    @CustomType.Constructor
    private GetClustersClusterOptionAdmissionControllerOption(@CustomType.Parameter("isPodSecurityPolicyEnabled") Boolean isPodSecurityPolicyEnabled) {
        this.isPodSecurityPolicyEnabled = isPodSecurityPolicyEnabled;
    }

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

    public static final class Builder {
        private Boolean isPodSecurityPolicyEnabled;

        public Builder() {
    	      // Empty
        }

        public Builder(GetClustersClusterOptionAdmissionControllerOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isPodSecurityPolicyEnabled = defaults.isPodSecurityPolicyEnabled;
        }

        public Builder isPodSecurityPolicyEnabled(Boolean isPodSecurityPolicyEnabled) {
            this.isPodSecurityPolicyEnabled = Objects.requireNonNull(isPodSecurityPolicyEnabled);
            return this;
        }        public GetClustersClusterOptionAdmissionControllerOption build() {
            return new GetClustersClusterOptionAdmissionControllerOption(isPodSecurityPolicyEnabled);
        }
    }
}
