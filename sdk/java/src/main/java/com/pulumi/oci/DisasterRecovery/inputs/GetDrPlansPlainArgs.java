// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DisasterRecovery.inputs.GetDrPlansFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDrPlansPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDrPlansPlainArgs Empty = new GetDrPlansPlainArgs();

    /**
     * A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid`
     * 
     */
    @Import(name="drPlanId")
    private @Nullable String drPlanId;

    /**
     * @return The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid`
     * 
     */
    public Optional<String> drPlanId() {
        return Optional.ofNullable(this.drPlanId);
    }

    /**
     * The DR Plan type.
     * 
     */
    @Import(name="drPlanType")
    private @Nullable String drPlanType;

    /**
     * @return The DR Plan type.
     * 
     */
    public Optional<String> drPlanType() {
        return Optional.ofNullable(this.drPlanType);
    }

    /**
     * The OCID of the DR Protection Group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
     * 
     */
    @Import(name="drProtectionGroupId", required=true)
    private String drProtectionGroupId;

    /**
     * @return The OCID of the DR Protection Group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
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
     * A filter to return only DR Plans that match the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only DR Plans that match the given lifecycleState.
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
         * @param displayName A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param drPlanId The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid`
         * 
         * @return builder
         * 
         */
        public Builder drPlanId(@Nullable String drPlanId) {
            $.drPlanId = drPlanId;
            return this;
        }

        /**
         * @param drPlanType The DR Plan type.
         * 
         * @return builder
         * 
         */
        public Builder drPlanType(@Nullable String drPlanType) {
            $.drPlanType = drPlanType;
            return this;
        }

        /**
         * @param drProtectionGroupId The OCID of the DR Protection Group. Mandatory query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
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
         * @param state A filter to return only DR Plans that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetDrPlansPlainArgs build() {
            $.drProtectionGroupId = Objects.requireNonNull($.drProtectionGroupId, "expected parameter 'drProtectionGroupId' to be non-null");
            return $;
        }
    }

}