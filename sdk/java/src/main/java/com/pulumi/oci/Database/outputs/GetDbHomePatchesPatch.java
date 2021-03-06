// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbHomePatchesPatch {
    /**
     * @return Actions that can possibly be performed using this patch.
     * 
     */
    private final List<String> availableActions;
    /**
     * @return The text describing this patch package.
     * 
     */
    private final String description;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch.
     * 
     */
    private final String id;
    /**
     * @return Action that is currently being performed or was completed last.
     * 
     */
    private final String lastAction;
    /**
     * @return A descriptive text associated with the lifecycleState. Typically can contain additional displayable text.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return The current state of the patch as a result of lastAction.
     * 
     */
    private final String state;
    /**
     * @return The date and time that the patch was released.
     * 
     */
    private final String timeReleased;
    /**
     * @return The version of this patch package.
     * 
     */
    private final String version;

    @CustomType.Constructor
    private GetDbHomePatchesPatch(
        @CustomType.Parameter("availableActions") List<String> availableActions,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("lastAction") String lastAction,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeReleased") String timeReleased,
        @CustomType.Parameter("version") String version) {
        this.availableActions = availableActions;
        this.description = description;
        this.id = id;
        this.lastAction = lastAction;
        this.lifecycleDetails = lifecycleDetails;
        this.state = state;
        this.timeReleased = timeReleased;
        this.version = version;
    }

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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch.
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

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbHomePatchesPatch defaults) {
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
        private String version;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDbHomePatchesPatch defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availableActions = defaults.availableActions;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.lastAction = defaults.lastAction;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.timeReleased = defaults.timeReleased;
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
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }        public GetDbHomePatchesPatch build() {
            return new GetDbHomePatchesPatch(availableActions, description, id, lastAction, lifecycleDetails, state, timeReleased, version);
        }
    }
}
