// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrPlansDrPlanCollection;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrPlansFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDrPlansResult {
    /**
     * @return The display name of the group.  Example: `DATABASE_SWITCHOVER`
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of dr_plan_collection.
     * 
     */
    private List<GetDrPlansDrPlanCollection> drPlanCollections;
    private @Nullable String drPlanId;
    private @Nullable String drPlanType;
    /**
     * @return The OCID of the DR protection group to which this DR plan belongs.  Example: `ocid1.drplan.oc1..uniqueID`
     * 
     */
    private String drProtectionGroupId;
    private @Nullable List<GetDrPlansFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the DR plan.
     * 
     */
    private @Nullable String lifecycleSubState;
    /**
     * @return The current state of the DR plan.
     * 
     */
    private @Nullable String state;

    private GetDrPlansResult() {}
    /**
     * @return The display name of the group.  Example: `DATABASE_SWITCHOVER`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of dr_plan_collection.
     * 
     */
    public List<GetDrPlansDrPlanCollection> drPlanCollections() {
        return this.drPlanCollections;
    }
    public Optional<String> drPlanId() {
        return Optional.ofNullable(this.drPlanId);
    }
    public Optional<String> drPlanType() {
        return Optional.ofNullable(this.drPlanType);
    }
    /**
     * @return The OCID of the DR protection group to which this DR plan belongs.  Example: `ocid1.drplan.oc1..uniqueID`
     * 
     */
    public String drProtectionGroupId() {
        return this.drProtectionGroupId;
    }
    public List<GetDrPlansFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The current state of the DR plan.
     * 
     */
    public Optional<String> lifecycleSubState() {
        return Optional.ofNullable(this.lifecycleSubState);
    }
    /**
     * @return The current state of the DR plan.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrPlansResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private List<GetDrPlansDrPlanCollection> drPlanCollections;
        private @Nullable String drPlanId;
        private @Nullable String drPlanType;
        private String drProtectionGroupId;
        private @Nullable List<GetDrPlansFilter> filters;
        private String id;
        private @Nullable String lifecycleSubState;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetDrPlansResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.drPlanCollections = defaults.drPlanCollections;
    	      this.drPlanId = defaults.drPlanId;
    	      this.drPlanType = defaults.drPlanType;
    	      this.drProtectionGroupId = defaults.drProtectionGroupId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.lifecycleSubState = defaults.lifecycleSubState;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder drPlanCollections(List<GetDrPlansDrPlanCollection> drPlanCollections) {
            if (drPlanCollections == null) {
              throw new MissingRequiredPropertyException("GetDrPlansResult", "drPlanCollections");
            }
            this.drPlanCollections = drPlanCollections;
            return this;
        }
        public Builder drPlanCollections(GetDrPlansDrPlanCollection... drPlanCollections) {
            return drPlanCollections(List.of(drPlanCollections));
        }
        @CustomType.Setter
        public Builder drPlanId(@Nullable String drPlanId) {

            this.drPlanId = drPlanId;
            return this;
        }
        @CustomType.Setter
        public Builder drPlanType(@Nullable String drPlanType) {

            this.drPlanType = drPlanType;
            return this;
        }
        @CustomType.Setter
        public Builder drProtectionGroupId(String drProtectionGroupId) {
            if (drProtectionGroupId == null) {
              throw new MissingRequiredPropertyException("GetDrPlansResult", "drProtectionGroupId");
            }
            this.drProtectionGroupId = drProtectionGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDrPlansFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDrPlansFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDrPlansResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleSubState(@Nullable String lifecycleSubState) {

            this.lifecycleSubState = lifecycleSubState;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetDrPlansResult build() {
            final var _resultValue = new GetDrPlansResult();
            _resultValue.displayName = displayName;
            _resultValue.drPlanCollections = drPlanCollections;
            _resultValue.drPlanId = drPlanId;
            _resultValue.drPlanType = drPlanType;
            _resultValue.drProtectionGroupId = drProtectionGroupId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.lifecycleSubState = lifecycleSubState;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
