// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class VmClusterAddVirtualNetworkCloudAutomationUpdateDetailApplyUpdateTimePreference {
    /**
     * @return End time for polling VM cloud automation software updates for the cluster. If the endTime is not specified, 2 AM UTC is used by default.
     * 
     */
    private @Nullable String applyUpdatePreferredEndTime;
    /**
     * @return Start time for polling VM cloud automation software updates for the cluster. If the startTime is not specified, 12 AM UTC is used by default.
     * 
     */
    private @Nullable String applyUpdatePreferredStartTime;

    private VmClusterAddVirtualNetworkCloudAutomationUpdateDetailApplyUpdateTimePreference() {}
    /**
     * @return End time for polling VM cloud automation software updates for the cluster. If the endTime is not specified, 2 AM UTC is used by default.
     * 
     */
    public Optional<String> applyUpdatePreferredEndTime() {
        return Optional.ofNullable(this.applyUpdatePreferredEndTime);
    }
    /**
     * @return Start time for polling VM cloud automation software updates for the cluster. If the startTime is not specified, 12 AM UTC is used by default.
     * 
     */
    public Optional<String> applyUpdatePreferredStartTime() {
        return Optional.ofNullable(this.applyUpdatePreferredStartTime);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VmClusterAddVirtualNetworkCloudAutomationUpdateDetailApplyUpdateTimePreference defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String applyUpdatePreferredEndTime;
        private @Nullable String applyUpdatePreferredStartTime;
        public Builder() {}
        public Builder(VmClusterAddVirtualNetworkCloudAutomationUpdateDetailApplyUpdateTimePreference defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applyUpdatePreferredEndTime = defaults.applyUpdatePreferredEndTime;
    	      this.applyUpdatePreferredStartTime = defaults.applyUpdatePreferredStartTime;
        }

        @CustomType.Setter
        public Builder applyUpdatePreferredEndTime(@Nullable String applyUpdatePreferredEndTime) {

            this.applyUpdatePreferredEndTime = applyUpdatePreferredEndTime;
            return this;
        }
        @CustomType.Setter
        public Builder applyUpdatePreferredStartTime(@Nullable String applyUpdatePreferredStartTime) {

            this.applyUpdatePreferredStartTime = applyUpdatePreferredStartTime;
            return this;
        }
        public VmClusterAddVirtualNetworkCloudAutomationUpdateDetailApplyUpdateTimePreference build() {
            final var _resultValue = new VmClusterAddVirtualNetworkCloudAutomationUpdateDetailApplyUpdateTimePreference();
            _resultValue.applyUpdatePreferredEndTime = applyUpdatePreferredEndTime;
            _resultValue.applyUpdatePreferredStartTime = applyUpdatePreferredStartTime;
            return _resultValue;
        }
    }
}
