// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetScheduledActionsFilter;
import com.pulumi.oci.Database.outputs.GetScheduledActionsScheduledActionCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetScheduledActionsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The display name of the Scheduled Action.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetScheduledActionsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduled Action.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of scheduled_action_collection.
     * 
     */
    private List<GetScheduledActionsScheduledActionCollection> scheduledActionCollections;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    private @Nullable String schedulingPlanId;
    private @Nullable String serviceType;
    /**
     * @return The current state of the Scheduled Action. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    private @Nullable String state;

    private GetScheduledActionsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The display name of the Scheduled Action.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetScheduledActionsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduled Action.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of scheduled_action_collection.
     * 
     */
    public List<GetScheduledActionsScheduledActionCollection> scheduledActionCollections() {
        return this.scheduledActionCollections;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    public Optional<String> schedulingPlanId() {
        return Optional.ofNullable(this.schedulingPlanId);
    }
    public Optional<String> serviceType() {
        return Optional.ofNullable(this.serviceType);
    }
    /**
     * @return The current state of the Scheduled Action. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScheduledActionsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetScheduledActionsFilter> filters;
        private @Nullable String id;
        private List<GetScheduledActionsScheduledActionCollection> scheduledActionCollections;
        private @Nullable String schedulingPlanId;
        private @Nullable String serviceType;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetScheduledActionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.scheduledActionCollections = defaults.scheduledActionCollections;
    	      this.schedulingPlanId = defaults.schedulingPlanId;
    	      this.serviceType = defaults.serviceType;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetScheduledActionsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetScheduledActionsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetScheduledActionsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder scheduledActionCollections(List<GetScheduledActionsScheduledActionCollection> scheduledActionCollections) {
            if (scheduledActionCollections == null) {
              throw new MissingRequiredPropertyException("GetScheduledActionsResult", "scheduledActionCollections");
            }
            this.scheduledActionCollections = scheduledActionCollections;
            return this;
        }
        public Builder scheduledActionCollections(GetScheduledActionsScheduledActionCollection... scheduledActionCollections) {
            return scheduledActionCollections(List.of(scheduledActionCollections));
        }
        @CustomType.Setter
        public Builder schedulingPlanId(@Nullable String schedulingPlanId) {

            this.schedulingPlanId = schedulingPlanId;
            return this;
        }
        @CustomType.Setter
        public Builder serviceType(@Nullable String serviceType) {

            this.serviceType = serviceType;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetScheduledActionsResult build() {
            final var _resultValue = new GetScheduledActionsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.scheduledActionCollections = scheduledActionCollections;
            _resultValue.schedulingPlanId = schedulingPlanId;
            _resultValue.serviceType = serviceType;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
