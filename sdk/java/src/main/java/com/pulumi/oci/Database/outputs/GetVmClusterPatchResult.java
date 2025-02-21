// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVmClusterPatchResult {
    /**
     * @return Actions that can possibly be performed using this patch.
     * 
     */
    private List<String> availableActions;
    /**
     * @return The text describing this patch package.
     * 
     */
    private String description;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Action that is currently being performed or was completed last.
     * 
     */
    private String lastAction;
    /**
     * @return A descriptive text associated with the lifecycleState. Typically can contain additional displayable text.
     * 
     */
    private String lifecycleDetails;
    private String patchId;
    /**
     * @return The current state of the patch as a result of lastAction.
     * 
     */
    private String state;
    /**
     * @return The date and time that the patch was released.
     * 
     */
    private String timeReleased;
    /**
     * @return The version of this patch package.
     * 
     */
    private String version;
    private String vmClusterId;

    private GetVmClusterPatchResult() {}
    /**
     * @return Actions that can possibly be performed using this patch.
     * 
     */
    public List<String> availableActions() {
        return this.availableActions;
    }
    /**
     * @return The text describing this patch package.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Action that is currently being performed or was completed last.
     * 
     */
    public String lastAction() {
        return this.lastAction;
    }
    /**
     * @return A descriptive text associated with the lifecycleState. Typically can contain additional displayable text.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public String patchId() {
        return this.patchId;
    }
    /**
     * @return The current state of the patch as a result of lastAction.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time that the patch was released.
     * 
     */
    public String timeReleased() {
        return this.timeReleased;
    }
    /**
     * @return The version of this patch package.
     * 
     */
    public String version() {
        return this.version;
    }
    public String vmClusterId() {
        return this.vmClusterId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVmClusterPatchResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> availableActions;
        private String description;
        private String id;
        private String lastAction;
        private String lifecycleDetails;
        private String patchId;
        private String state;
        private String timeReleased;
        private String version;
        private String vmClusterId;
        public Builder() {}
        public Builder(GetVmClusterPatchResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availableActions = defaults.availableActions;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.lastAction = defaults.lastAction;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.patchId = defaults.patchId;
    	      this.state = defaults.state;
    	      this.timeReleased = defaults.timeReleased;
    	      this.version = defaults.version;
    	      this.vmClusterId = defaults.vmClusterId;
        }

        @CustomType.Setter
        public Builder availableActions(List<String> availableActions) {
            if (availableActions == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "availableActions");
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
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lastAction(String lastAction) {
            if (lastAction == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "lastAction");
            }
            this.lastAction = lastAction;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder patchId(String patchId) {
            if (patchId == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "patchId");
            }
            this.patchId = patchId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeReleased(String timeReleased) {
            if (timeReleased == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "timeReleased");
            }
            this.timeReleased = timeReleased;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "version");
            }
            this.version = version;
            return this;
        }
        @CustomType.Setter
        public Builder vmClusterId(String vmClusterId) {
            if (vmClusterId == null) {
              throw new MissingRequiredPropertyException("GetVmClusterPatchResult", "vmClusterId");
            }
            this.vmClusterId = vmClusterId;
            return this;
        }
        public GetVmClusterPatchResult build() {
            final var _resultValue = new GetVmClusterPatchResult();
            _resultValue.availableActions = availableActions;
            _resultValue.description = description;
            _resultValue.id = id;
            _resultValue.lastAction = lastAction;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.patchId = patchId;
            _resultValue.state = state;
            _resultValue.timeReleased = timeReleased;
            _resultValue.version = version;
            _resultValue.vmClusterId = vmClusterId;
            return _resultValue;
        }
    }
}
