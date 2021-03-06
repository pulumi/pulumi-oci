// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVmClusterUpdatesVmClusterUpdate {
    /**
     * @return The possible actions that can be performed using this maintenance update.
     * 
     */
    private final List<String> availableActions;
    /**
     * @return Details of the maintenance update package.
     * 
     */
    private final String description;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update.
     * 
     */
    private final String id;
    /**
     * @return The update action performed most recently using this maintenance update.
     * 
     */
    private final String lastAction;
    /**
     * @return Descriptive text providing additional details about the lifecycle state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    private final String state;
    /**
     * @return The date and time the maintenance update was released.
     * 
     */
    private final String timeReleased;
    /**
     * @return A filter to return only resources that match the given update type exactly.
     * 
     */
    private final String updateType;
    /**
     * @return The version of the maintenance update package.
     * 
     */
    private final String version;

    @CustomType.Constructor
    private GetVmClusterUpdatesVmClusterUpdate(
        @CustomType.Parameter("availableActions") List<String> availableActions,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("lastAction") String lastAction,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeReleased") String timeReleased,
        @CustomType.Parameter("updateType") String updateType,
        @CustomType.Parameter("version") String version) {
        this.availableActions = availableActions;
        this.description = description;
        this.id = id;
        this.lastAction = lastAction;
        this.lifecycleDetails = lifecycleDetails;
        this.state = state;
        this.timeReleased = timeReleased;
        this.updateType = updateType;
        this.version = version;
    }

    /**
     * @return The possible actions that can be performed using this maintenance update.
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
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The update action performed most recently using this maintenance update.
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
     * @return A filter to return only resources that match the given lifecycle state exactly.
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
    /**
     * @return A filter to return only resources that match the given update type exactly.
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

    public static Builder builder(GetVmClusterUpdatesVmClusterUpdate defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<String> availableActions;
        private String description;
        private String id;
        private String lastAction;
        private String lifecycleDetails;
        private String state;
        private String timeReleased;
        private String updateType;
        private String version;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVmClusterUpdatesVmClusterUpdate defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availableActions = defaults.availableActions;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.lastAction = defaults.lastAction;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.timeReleased = defaults.timeReleased;
    	      this.updateType = defaults.updateType;
    	      this.version = defaults.version;
        }

        public Builder availableActions(List<String> availableActions) {
            this.availableActions = Objects.requireNonNull(availableActions);
            return this;
        }
        public Builder availableActions(String... availableActions) {
            return availableActions(List.of(availableActions));
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder lastAction(String lastAction) {
            this.lastAction = Objects.requireNonNull(lastAction);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeReleased(String timeReleased) {
            this.timeReleased = Objects.requireNonNull(timeReleased);
            return this;
        }
        public Builder updateType(String updateType) {
            this.updateType = Objects.requireNonNull(updateType);
            return this;
        }
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }        public GetVmClusterUpdatesVmClusterUpdate build() {
            return new GetVmClusterUpdatesVmClusterUpdate(availableActions, description, id, lastAction, lifecycleDetails, state, timeReleased, updateType, version);
        }
    }
}
