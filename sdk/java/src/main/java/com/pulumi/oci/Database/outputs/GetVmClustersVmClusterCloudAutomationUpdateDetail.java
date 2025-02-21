// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetVmClustersVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreference;
import com.pulumi.oci.Database.outputs.GetVmClustersVmClusterCloudAutomationUpdateDetailFreezePeriod;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVmClustersVmClusterCloudAutomationUpdateDetail {
    /**
     * @return Configure the time slot for applying VM cloud automation software updates to the cluster. When nothing is selected, the default time slot is 12 AM to 2 AM UTC. Any 2-hour slot is available starting at 12 AM.
     * 
     */
    private List<GetVmClustersVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreference> applyUpdateTimePreferences;
    /**
     * @return Enables a freeze period for the VM cluster prohibiting the VMs from getting cloud automation software updates during critical business cycles. Freeze period start date. Starts at 12:00 AM UTC on the selected date and ends at 11:59:59 PM UTC on the selected date. Validates to ensure the freeze period does not exceed 45 days.
     * 
     */
    private List<GetVmClustersVmClusterCloudAutomationUpdateDetailFreezePeriod> freezePeriods;
    /**
     * @return Annotates whether the cluster should be part of early access to apply VM cloud automation software updates. Those clusters annotated as early access will download the software bits for cloud automation in the first week after the update is available, while other clusters will have to wait until the following week.
     * 
     */
    private Boolean isEarlyAdoptionEnabled;
    /**
     * @return Specifies if the freeze period is enabled for the VM cluster to prevent the VMs from receiving cloud automation software updates during critical business cycles. Freeze period starts at 12:00 AM UTC and ends at 11:59:59 PM UTC on the selected date. Ensure that the freezing period does not exceed 45 days.
     * 
     */
    private Boolean isFreezePeriodEnabled;

    private GetVmClustersVmClusterCloudAutomationUpdateDetail() {}
    /**
     * @return Configure the time slot for applying VM cloud automation software updates to the cluster. When nothing is selected, the default time slot is 12 AM to 2 AM UTC. Any 2-hour slot is available starting at 12 AM.
     * 
     */
    public List<GetVmClustersVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreference> applyUpdateTimePreferences() {
        return this.applyUpdateTimePreferences;
    }
    /**
     * @return Enables a freeze period for the VM cluster prohibiting the VMs from getting cloud automation software updates during critical business cycles. Freeze period start date. Starts at 12:00 AM UTC on the selected date and ends at 11:59:59 PM UTC on the selected date. Validates to ensure the freeze period does not exceed 45 days.
     * 
     */
    public List<GetVmClustersVmClusterCloudAutomationUpdateDetailFreezePeriod> freezePeriods() {
        return this.freezePeriods;
    }
    /**
     * @return Annotates whether the cluster should be part of early access to apply VM cloud automation software updates. Those clusters annotated as early access will download the software bits for cloud automation in the first week after the update is available, while other clusters will have to wait until the following week.
     * 
     */
    public Boolean isEarlyAdoptionEnabled() {
        return this.isEarlyAdoptionEnabled;
    }
    /**
     * @return Specifies if the freeze period is enabled for the VM cluster to prevent the VMs from receiving cloud automation software updates during critical business cycles. Freeze period starts at 12:00 AM UTC and ends at 11:59:59 PM UTC on the selected date. Ensure that the freezing period does not exceed 45 days.
     * 
     */
    public Boolean isFreezePeriodEnabled() {
        return this.isFreezePeriodEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVmClustersVmClusterCloudAutomationUpdateDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetVmClustersVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreference> applyUpdateTimePreferences;
        private List<GetVmClustersVmClusterCloudAutomationUpdateDetailFreezePeriod> freezePeriods;
        private Boolean isEarlyAdoptionEnabled;
        private Boolean isFreezePeriodEnabled;
        public Builder() {}
        public Builder(GetVmClustersVmClusterCloudAutomationUpdateDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applyUpdateTimePreferences = defaults.applyUpdateTimePreferences;
    	      this.freezePeriods = defaults.freezePeriods;
    	      this.isEarlyAdoptionEnabled = defaults.isEarlyAdoptionEnabled;
    	      this.isFreezePeriodEnabled = defaults.isFreezePeriodEnabled;
        }

        @CustomType.Setter
        public Builder applyUpdateTimePreferences(List<GetVmClustersVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreference> applyUpdateTimePreferences) {
            if (applyUpdateTimePreferences == null) {
              throw new MissingRequiredPropertyException("GetVmClustersVmClusterCloudAutomationUpdateDetail", "applyUpdateTimePreferences");
            }
            this.applyUpdateTimePreferences = applyUpdateTimePreferences;
            return this;
        }
        public Builder applyUpdateTimePreferences(GetVmClustersVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreference... applyUpdateTimePreferences) {
            return applyUpdateTimePreferences(List.of(applyUpdateTimePreferences));
        }
        @CustomType.Setter
        public Builder freezePeriods(List<GetVmClustersVmClusterCloudAutomationUpdateDetailFreezePeriod> freezePeriods) {
            if (freezePeriods == null) {
              throw new MissingRequiredPropertyException("GetVmClustersVmClusterCloudAutomationUpdateDetail", "freezePeriods");
            }
            this.freezePeriods = freezePeriods;
            return this;
        }
        public Builder freezePeriods(GetVmClustersVmClusterCloudAutomationUpdateDetailFreezePeriod... freezePeriods) {
            return freezePeriods(List.of(freezePeriods));
        }
        @CustomType.Setter
        public Builder isEarlyAdoptionEnabled(Boolean isEarlyAdoptionEnabled) {
            if (isEarlyAdoptionEnabled == null) {
              throw new MissingRequiredPropertyException("GetVmClustersVmClusterCloudAutomationUpdateDetail", "isEarlyAdoptionEnabled");
            }
            this.isEarlyAdoptionEnabled = isEarlyAdoptionEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isFreezePeriodEnabled(Boolean isFreezePeriodEnabled) {
            if (isFreezePeriodEnabled == null) {
              throw new MissingRequiredPropertyException("GetVmClustersVmClusterCloudAutomationUpdateDetail", "isFreezePeriodEnabled");
            }
            this.isFreezePeriodEnabled = isFreezePeriodEnabled;
            return this;
        }
        public GetVmClustersVmClusterCloudAutomationUpdateDetail build() {
            final var _resultValue = new GetVmClustersVmClusterCloudAutomationUpdateDetail();
            _resultValue.applyUpdateTimePreferences = applyUpdateTimePreferences;
            _resultValue.freezePeriods = freezePeriods;
            _resultValue.isEarlyAdoptionEnabled = isEarlyAdoptionEnabled;
            _resultValue.isFreezePeriodEnabled = isFreezePeriodEnabled;
            return _resultValue;
        }
    }
}
