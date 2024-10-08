// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExadbVmClusterUpdateResult {
    /**
     * @return The possible actions performed by the update operation on the infrastructure components.
     * 
     */
    private List<String> availableActions;
    /**
     * @return Details of the maintenance update package.
     * 
     */
    private String description;
    private String exadbVmClusterId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The previous update action performed.
     * 
     */
    private String lastAction;
    /**
     * @return Descriptive text providing additional details about the lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The current state of the maintenance update. Dependent on value of `lastAction`.
     * 
     */
    private String state;
    /**
     * @return The date and time the maintenance update was released.
     * 
     */
    private String timeReleased;
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

    private GetExadbVmClusterUpdateResult() {}
    /**
     * @return The possible actions performed by the update operation on the infrastructure components.
     * 
     */
    public List<String> availableActions() {
        return this.availableActions;
    }
    /**
     * @return Details of the maintenance update package.
     * 
     */
    public String description() {
        return this.description;
    }
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
     * @return The previous update action performed.
     * 
     */
    public String lastAction() {
        return this.lastAction;
    }
    /**
     * @return Descriptive text providing additional details about the lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The current state of the maintenance update. Dependent on value of `lastAction`.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the maintenance update was released.
     * 
     */
    public String timeReleased() {
        return this.timeReleased;
    }
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

    public static Builder builder(GetExadbVmClusterUpdateResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> availableActions;
        private String description;
        private String exadbVmClusterId;
        private String id;
        private String lastAction;
        private String lifecycleDetails;
        private String state;
        private String timeReleased;
        private String updateId;
        private String updateType;
        private String version;
        public Builder() {}
        public Builder(GetExadbVmClusterUpdateResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availableActions = defaults.availableActions;
    	      this.description = defaults.description;
    	      this.exadbVmClusterId = defaults.exadbVmClusterId;
    	      this.id = defaults.id;
    	      this.lastAction = defaults.lastAction;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.timeReleased = defaults.timeReleased;
    	      this.updateId = defaults.updateId;
    	      this.updateType = defaults.updateType;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder availableActions(List<String> availableActions) {
            if (availableActions == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "availableActions");
            }
            this.availableActions = availableActions;
            return this;
        }
        public Builder availableActions(String... availableActions) {
            return availableActions(List.of(availableActions));
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder exadbVmClusterId(String exadbVmClusterId) {
            if (exadbVmClusterId == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "exadbVmClusterId");
            }
            this.exadbVmClusterId = exadbVmClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lastAction(String lastAction) {
            if (lastAction == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "lastAction");
            }
            this.lastAction = lastAction;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeReleased(String timeReleased) {
            if (timeReleased == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "timeReleased");
            }
            this.timeReleased = timeReleased;
            return this;
        }
        @CustomType.Setter
        public Builder updateId(String updateId) {
            if (updateId == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "updateId");
            }
            this.updateId = updateId;
            return this;
        }
        @CustomType.Setter
        public Builder updateType(String updateType) {
            if (updateType == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "updateType");
            }
            this.updateType = updateType;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClusterUpdateResult", "version");
            }
            this.version = version;
            return this;
        }
        public GetExadbVmClusterUpdateResult build() {
            final var _resultValue = new GetExadbVmClusterUpdateResult();
            _resultValue.availableActions = availableActions;
            _resultValue.description = description;
            _resultValue.exadbVmClusterId = exadbVmClusterId;
            _resultValue.id = id;
            _resultValue.lastAction = lastAction;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.state = state;
            _resultValue.timeReleased = timeReleased;
            _resultValue.updateId = updateId;
            _resultValue.updateType = updateType;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
