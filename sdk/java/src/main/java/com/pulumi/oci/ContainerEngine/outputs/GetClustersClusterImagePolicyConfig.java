// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerEngine.outputs.GetClustersClusterImagePolicyConfigKeyDetail;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetClustersClusterImagePolicyConfig {
    /**
     * @return Whether the image verification policy is enabled. Defaults to false. If set to true, the images will be verified against the policy at runtime.
     * 
     */
    private Boolean isPolicyEnabled;
    /**
     * @return A list of KMS key details.
     * 
     */
    private List<GetClustersClusterImagePolicyConfigKeyDetail> keyDetails;

    private GetClustersClusterImagePolicyConfig() {}
    /**
     * @return Whether the image verification policy is enabled. Defaults to false. If set to true, the images will be verified against the policy at runtime.
     * 
     */
    public Boolean isPolicyEnabled() {
        return this.isPolicyEnabled;
    }
    /**
     * @return A list of KMS key details.
     * 
     */
    public List<GetClustersClusterImagePolicyConfigKeyDetail> keyDetails() {
        return this.keyDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClustersClusterImagePolicyConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isPolicyEnabled;
        private List<GetClustersClusterImagePolicyConfigKeyDetail> keyDetails;
        public Builder() {}
        public Builder(GetClustersClusterImagePolicyConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isPolicyEnabled = defaults.isPolicyEnabled;
    	      this.keyDetails = defaults.keyDetails;
        }

        @CustomType.Setter
        public Builder isPolicyEnabled(Boolean isPolicyEnabled) {
            this.isPolicyEnabled = Objects.requireNonNull(isPolicyEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder keyDetails(List<GetClustersClusterImagePolicyConfigKeyDetail> keyDetails) {
            this.keyDetails = Objects.requireNonNull(keyDetails);
            return this;
        }
        public Builder keyDetails(GetClustersClusterImagePolicyConfigKeyDetail... keyDetails) {
            return keyDetails(List.of(keyDetails));
        }
        public GetClustersClusterImagePolicyConfig build() {
            final var o = new GetClustersClusterImagePolicyConfig();
            o.isPolicyEnabled = isPolicyEnabled;
            o.keyDetails = keyDetails;
            return o;
        }
    }
}