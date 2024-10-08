// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail {
    /**
     * @return Estimated time, in minutes, to patch one database server.
     * 
     */
    private Integer estimatedPatchDuration;
    /**
     * @return The status of the patching operation.
     * 
     */
    private String patchingStatus;
    /**
     * @return The time when the patching operation ended.
     * 
     */
    private String timePatchingEnded;
    /**
     * @return The time when the patching operation started.
     * 
     */
    private String timePatchingStarted;

    private GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail() {}
    /**
     * @return Estimated time, in minutes, to patch one database server.
     * 
     */
    public Integer estimatedPatchDuration() {
        return this.estimatedPatchDuration;
    }
    /**
     * @return The status of the patching operation.
     * 
     */
    public String patchingStatus() {
        return this.patchingStatus;
    }
    /**
     * @return The time when the patching operation ended.
     * 
     */
    public String timePatchingEnded() {
        return this.timePatchingEnded;
    }
    /**
     * @return The time when the patching operation started.
     * 
     */
    public String timePatchingStarted() {
        return this.timePatchingStarted;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer estimatedPatchDuration;
        private String patchingStatus;
        private String timePatchingEnded;
        private String timePatchingStarted;
        public Builder() {}
        public Builder(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.estimatedPatchDuration = defaults.estimatedPatchDuration;
    	      this.patchingStatus = defaults.patchingStatus;
    	      this.timePatchingEnded = defaults.timePatchingEnded;
    	      this.timePatchingStarted = defaults.timePatchingStarted;
        }

        @CustomType.Setter
        public Builder estimatedPatchDuration(Integer estimatedPatchDuration) {
            if (estimatedPatchDuration == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail", "estimatedPatchDuration");
            }
            this.estimatedPatchDuration = estimatedPatchDuration;
            return this;
        }
        @CustomType.Setter
        public Builder patchingStatus(String patchingStatus) {
            if (patchingStatus == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail", "patchingStatus");
            }
            this.patchingStatus = patchingStatus;
            return this;
        }
        @CustomType.Setter
        public Builder timePatchingEnded(String timePatchingEnded) {
            if (timePatchingEnded == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail", "timePatchingEnded");
            }
            this.timePatchingEnded = timePatchingEnded;
            return this;
        }
        @CustomType.Setter
        public Builder timePatchingStarted(String timePatchingStarted) {
            if (timePatchingStarted == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail", "timePatchingStarted");
            }
            this.timePatchingStarted = timePatchingStarted;
            return this;
        }
        public GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail build() {
            final var _resultValue = new GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetail();
            _resultValue.estimatedPatchDuration = estimatedPatchDuration;
            _resultValue.patchingStatus = patchingStatus;
            _resultValue.timePatchingEnded = timePatchingEnded;
            _resultValue.timePatchingStarted = timePatchingStarted;
            return _resultValue;
        }
    }
}
