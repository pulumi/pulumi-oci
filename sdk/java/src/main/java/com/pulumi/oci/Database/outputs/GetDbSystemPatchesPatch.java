// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbSystemPatchesPatch {
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch.
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

    private GetDbSystemPatchesPatch() {}
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

    public static Builder builder(GetDbSystemPatchesPatch defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> availableActions;
        private String description;
        private String id;
        private String lastAction;
        private String lifecycleDetails;
        private String state;
        private String timeReleased;
        private String version;
        public Builder() {}
        public Builder(GetDbSystemPatchesPatch defaults) {
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

        @CustomType.Setter
        public Builder availableActions(List<String> availableActions) {
            this.availableActions = Objects.requireNonNull(availableActions);
            return this;
        }
        public Builder availableActions(String... availableActions) {
            return availableActions(List.of(availableActions));
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lastAction(String lastAction) {
            this.lastAction = Objects.requireNonNull(lastAction);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeReleased(String timeReleased) {
            this.timeReleased = Objects.requireNonNull(timeReleased);
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }
        public GetDbSystemPatchesPatch build() {
            final var o = new GetDbSystemPatchesPatch();
            o.availableActions = availableActions;
            o.description = description;
            o.id = id;
            o.lastAction = lastAction;
            o.lifecycleDetails = lifecycleDetails;
            o.state = state;
            o.timeReleased = timeReleased;
            o.version = version;
            return o;
        }
    }
}