// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExadbVmClusterUpdateHistoryEntryResult {
    private String exadbVmClusterId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Descriptive text providing additional details about the lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The current lifecycle state of the maintenance update operation.
     * 
     */
    private String state;
    /**
     * @return The date and time when the maintenance update action completed.
     * 
     */
    private String timeCompleted;
    /**
     * @return The date and time when the maintenance update action started.
     * 
     */
    private String timeStarted;
    /**
     * @return The update action.
     * 
     */
    private String updateAction;
    private String updateHistoryEntryId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update.
     * 
     */
    private String updateId;
    /**
     * @return The type of cloud VM cluster maintenance update.
     * 
     */
    private String updateType;
    /**
     * @return The version of the maintenance update package.
     * 
     */
    private String version;

    private GetExadbVmClusterUpdateHistoryEntryResult() {}
    public String exadbVmClusterId() {
        return this.exadbVmClusterId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Descriptive text providing additional details about the lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The current lifecycle state of the maintenance update operation.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time when the maintenance update action completed.
     * 
     */
    public String timeCompleted() {
        return this.timeCompleted;
    }
    /**
     * @return The date and time when the maintenance update action started.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return The update action.
     * 
     */
    public String updateAction() {
        return this.updateAction;
    }
    public String updateHistoryEntryId() {
        return this.updateHistoryEntryId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update.
     * 
     */
    public String updateId() {
        return this.updateId;
    }
    /**
     * @return The type of cloud VM cluster maintenance update.
     * 
     */
    public String updateType() {
        return this.updateType;
    }
    /**
     * @return The version of the maintenance update package.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExadbVmClusterUpdateHistoryEntryResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String exadbVmClusterId;
        private String id;
        private String lifecycleDetails;
        private String state;
        private String timeCompleted;
        private String timeStarted;
        private String updateAction;
        private String updateHistoryEntryId;
        private String updateId;
        private String updateType;
        private String version;
        public Builder() {}
        public Builder(GetExadbVmClusterUpdateHistoryEntryResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.exadbVmClusterId = defaults.exadbVmClusterId;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.timeCompleted = defaults.timeCompleted;
    	      this.timeStarted = defaults.timeStarted;
    	      this.updateAction = defaults.updateAction;
    	      this.updateHistoryEntryId = defaults.updateHistoryEntryId;
    	      this.updateId = defaults.updateId;
    	      this.updateType = defaults.updateType;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder exadbVmClusterId(String exadbVmClusterId) {
            if (exadbVmClusterId == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "exadbVmClusterId");
            }
            this.exadbVmClusterId = exadbVmClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCompleted(String timeCompleted) {
            if (timeCompleted == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "timeCompleted");
            }
            this.timeCompleted = timeCompleted;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            if (timeStarted == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "timeStarted");
            }
            this.timeStarted = timeStarted;
            return this;
        }
        @CustomType.Setter
        public Builder updateAction(String updateAction) {
            if (updateAction == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "updateAction");
            }
            this.updateAction = updateAction;
            return this;
        }
        @CustomType.Setter
        public Builder updateHistoryEntryId(String updateHistoryEntryId) {
            if (updateHistoryEntryId == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "updateHistoryEntryId");
            }
            this.updateHistoryEntryId = updateHistoryEntryId;
            return this;
        }
        @CustomType.Setter
        public Builder updateId(String updateId) {
            if (updateId == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "updateId");
            }
            this.updateId = updateId;
            return this;
        }
        @CustomType.Setter
        public Builder updateType(String updateType) {
            if (updateType == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "updateType");
            }
            this.updateType = updateType;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateHistoryEntryResult", "version");
            }
            this.version = version;
            return this;
        }
        public GetExadbVmClusterUpdateHistoryEntryResult build() {
            final var _resultValue = new GetExadbVmClusterUpdateHistoryEntryResult();
            _resultValue.exadbVmClusterId = exadbVmClusterId;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.state = state;
            _resultValue.timeCompleted = timeCompleted;
            _resultValue.timeStarted = timeStarted;
            _resultValue.updateAction = updateAction;
            _resultValue.updateHistoryEntryId = updateHistoryEntryId;
            _resultValue.updateId = updateId;
            _resultValue.updateType = updateType;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
