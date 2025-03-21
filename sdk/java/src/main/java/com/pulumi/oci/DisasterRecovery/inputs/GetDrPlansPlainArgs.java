// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DisasterRecovery.inputs.GetDrPlansFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDrPlansPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDrPlansPlainArgs Empty = new GetDrPlansPlainArgs();

    /**
     * A filter to return only resources that match the given display name.  Example: `MyResourceDisplayName`
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the given display name.  Example: `MyResourceDisplayName`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
     * 
     */
    @Import(name="drPlanId")
    private @Nullable String drPlanId;

    /**
     * @return The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
     * 
     */
    public Optional<String> drPlanId() {
        return Optional.ofNullable(this.drPlanId);
    }

    /**
     * The DR plan type.
     * 
     */
    @Import(name="drPlanType")
    private @Nullable String drPlanType;

    /**
     * @return The DR plan type.
     * 
     */
    public Optional<String> drPlanType() {
        return Optional.ofNullable(this.drPlanType);
    }

    /**
     * The OCID of the DR protection group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
     * 
     */
    @Import(name="drProtectionGroupId", required=true)
    private String drProtectionGroupId;

    /**
     * @return The OCID of the DR protection group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
     * 
     */
    public String drProtectionGroupId() {
        return this.drProtectionGroupId;
    }

    @Import(name="filters")
    private @Nullable List<GetDrPlansFilter> filters;

    public Optional<List<GetDrPlansFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only DR plans that match the given lifecycle sub-state.
     * 
     */
    @Import(name="lifecycleSubState")
    private @Nullable String lifecycleSubState;

    /**
     * @return A filter to return only DR plans that match the given lifecycle sub-state.
     * 
     */
    public Optional<String> lifecycleSubState() {
        return Optional.ofNullable(this.lifecycleSubState);
    }

    /**
     * A filter to return only DR plans that match the given lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only DR plans that match the given lifecycle state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetDrPlansPlainArgs() {}

    private GetDrPlansPlainArgs(GetDrPlansPlainArgs $) {
        this.displayName = $.displayName;
        this.drPlanId = $.drPlanId;
        this.drPlanType = $.drPlanType;
        this.drProtectionGroupId = $.drProtectionGroupId;
        this.filters = $.filters;
        this.lifecycleSubState = $.lifecycleSubState;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDrPlansPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDrPlansPlainArgs $;

        public Builder() {
            $ = new GetDrPlansPlainArgs();
        }

        public Builder(GetDrPlansPlainArgs defaults) {
            $ = new GetDrPlansPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only resources that match the given display name.  Example: `MyResourceDisplayName`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param drPlanId The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder drPlanId(@Nullable String drPlanId) {
            $.drPlanId = drPlanId;
            return this;
        }

        /**
         * @param drPlanType The DR plan type.
         * 
         * @return builder
         * 
         */
        public Builder drPlanType(@Nullable String drPlanType) {
            $.drPlanType = drPlanType;
            return this;
        }

        /**
         * @param drProtectionGroupId The OCID of the DR protection group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder drProtectionGroupId(String drProtectionGroupId) {
            $.drProtectionGroupId = drProtectionGroupId;
            return this;
        }

        public Builder filters(@Nullable List<GetDrPlansFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDrPlansFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param lifecycleSubState A filter to return only DR plans that match the given lifecycle sub-state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleSubState(@Nullable String lifecycleSubState) {
            $.lifecycleSubState = lifecycleSubState;
            return this;
        }

        /**
         * @param state A filter to return only DR plans that match the given lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetDrPlansPlainArgs build() {
            if ($.drProtectionGroupId == null) {
                throw new MissingRequiredPropertyException("GetDrPlansPlainArgs", "drProtectionGroupId");
            }
            return $;
        }
    }

}
