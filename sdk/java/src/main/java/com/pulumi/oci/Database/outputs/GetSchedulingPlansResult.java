// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetSchedulingPlansFilter;
import com.pulumi.oci.Database.outputs.GetSchedulingPlansSchedulingPlanCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSchedulingPlansResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The display name of the Scheduling Plan.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetSchedulingPlansFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    private @Nullable String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private @Nullable String resourceId;
    /**
     * @return The list of scheduling_plan_collection.
     * 
     */
    private List<GetSchedulingPlansSchedulingPlanCollection> schedulingPlanCollections;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Policy.
     * 
     */
    private @Nullable String schedulingPolicyId;
    /**
     * @return The current state of the Scheduling Plan. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    private @Nullable String state;

    private GetSchedulingPlansResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The display name of the Scheduling Plan.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetSchedulingPlansFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Optional<String> resourceId() {
        return Optional.ofNullable(this.resourceId);
    }
    /**
     * @return The list of scheduling_plan_collection.
     * 
     */
    public List<GetSchedulingPlansSchedulingPlanCollection> schedulingPlanCollections() {
        return this.schedulingPlanCollections;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Policy.
     * 
     */
    public Optional<String> schedulingPolicyId() {
        return Optional.ofNullable(this.schedulingPolicyId);
    }
    /**
     * @return The current state of the Scheduling Plan. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulingPlansResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetSchedulingPlansFilter> filters;
        private @Nullable String id;
        private @Nullable String resourceId;
        private List<GetSchedulingPlansSchedulingPlanCollection> schedulingPlanCollections;
        private @Nullable String schedulingPolicyId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetSchedulingPlansResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.resourceId = defaults.resourceId;
    	      this.schedulingPlanCollections = defaults.schedulingPlanCollections;
    	      this.schedulingPolicyId = defaults.schedulingPolicyId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPlansResult", "compartmentId");
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
        public Builder filters(@Nullable List<GetSchedulingPlansFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSchedulingPlansFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(@Nullable String resourceId) {

            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder schedulingPlanCollections(List<GetSchedulingPlansSchedulingPlanCollection> schedulingPlanCollections) {
            if (schedulingPlanCollections == null) {
              throw new MissingRequiredPropertyException("GetSchedulingPlansResult", "schedulingPlanCollections");
            }
            this.schedulingPlanCollections = schedulingPlanCollections;
            return this;
        }
        public Builder schedulingPlanCollections(GetSchedulingPlansSchedulingPlanCollection... schedulingPlanCollections) {
            return schedulingPlanCollections(List.of(schedulingPlanCollections));
        }
        @CustomType.Setter
        public Builder schedulingPolicyId(@Nullable String schedulingPolicyId) {

            this.schedulingPolicyId = schedulingPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetSchedulingPlansResult build() {
            final var _resultValue = new GetSchedulingPlansResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.resourceId = resourceId;
            _resultValue.schedulingPlanCollections = schedulingPlanCollections;
            _resultValue.schedulingPolicyId = schedulingPolicyId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
