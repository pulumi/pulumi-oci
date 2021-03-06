// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionAction {
    /**
     * @return Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. Defaults to false if not specified.
     * 
     */
    private final Boolean preserveBootVolume;
    /**
     * @return The type of action to run when the instance is interrupted for eviction.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionAction(
        @CustomType.Parameter("preserveBootVolume") Boolean preserveBootVolume,
        @CustomType.Parameter("type") String type) {
        this.preserveBootVolume = preserveBootVolume;
        this.type = type;
    }

    /**
     * @return Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. Defaults to false if not specified.
     * 
     */
    public Boolean preserveBootVolume() {
        return this.preserveBootVolume;
    }
    /**
     * @return The type of action to run when the instance is interrupted for eviction.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionAction defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean preserveBootVolume;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.preserveBootVolume = defaults.preserveBootVolume;
    	      this.type = defaults.type;
        }

        public Builder preserveBootVolume(Boolean preserveBootVolume) {
            this.preserveBootVolume = Objects.requireNonNull(preserveBootVolume);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionAction build() {
            return new GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionAction(preserveBootVolume, type);
        }
    }
}
