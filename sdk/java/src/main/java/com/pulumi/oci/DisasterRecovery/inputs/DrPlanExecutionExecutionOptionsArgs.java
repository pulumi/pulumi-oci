// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrPlanExecutionExecutionOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrPlanExecutionExecutionOptionsArgs Empty = new DrPlanExecutionExecutionOptionsArgs();

    /**
     * A flag indicating whether a precheck should be executed before the plan.  Example: `false`
     * 
     */
    @Import(name="arePrechecksEnabled")
    private @Nullable Output<Boolean> arePrechecksEnabled;

    /**
     * @return A flag indicating whether a precheck should be executed before the plan.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> arePrechecksEnabled() {
        return Optional.ofNullable(this.arePrechecksEnabled);
    }

    /**
     * A flag indicating whether warnigs should be ignored during the switchover.  Example: `true`
     * 
     */
    @Import(name="areWarningsIgnored")
    private @Nullable Output<Boolean> areWarningsIgnored;

    /**
     * @return A flag indicating whether warnigs should be ignored during the switchover.  Example: `true`
     * 
     */
    public Optional<Output<Boolean>> areWarningsIgnored() {
        return Optional.ofNullable(this.areWarningsIgnored);
    }

    /**
     * The type of the plan execution.
     * 
     */
    @Import(name="planExecutionType", required=true)
    private Output<String> planExecutionType;

    /**
     * @return The type of the plan execution.
     * 
     */
    public Output<String> planExecutionType() {
        return this.planExecutionType;
    }

    private DrPlanExecutionExecutionOptionsArgs() {}

    private DrPlanExecutionExecutionOptionsArgs(DrPlanExecutionExecutionOptionsArgs $) {
        this.arePrechecksEnabled = $.arePrechecksEnabled;
        this.areWarningsIgnored = $.areWarningsIgnored;
        this.planExecutionType = $.planExecutionType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrPlanExecutionExecutionOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrPlanExecutionExecutionOptionsArgs $;

        public Builder() {
            $ = new DrPlanExecutionExecutionOptionsArgs();
        }

        public Builder(DrPlanExecutionExecutionOptionsArgs defaults) {
            $ = new DrPlanExecutionExecutionOptionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param arePrechecksEnabled A flag indicating whether a precheck should be executed before the plan.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder arePrechecksEnabled(@Nullable Output<Boolean> arePrechecksEnabled) {
            $.arePrechecksEnabled = arePrechecksEnabled;
            return this;
        }

        /**
         * @param arePrechecksEnabled A flag indicating whether a precheck should be executed before the plan.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder arePrechecksEnabled(Boolean arePrechecksEnabled) {
            return arePrechecksEnabled(Output.of(arePrechecksEnabled));
        }

        /**
         * @param areWarningsIgnored A flag indicating whether warnigs should be ignored during the switchover.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder areWarningsIgnored(@Nullable Output<Boolean> areWarningsIgnored) {
            $.areWarningsIgnored = areWarningsIgnored;
            return this;
        }

        /**
         * @param areWarningsIgnored A flag indicating whether warnigs should be ignored during the switchover.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder areWarningsIgnored(Boolean areWarningsIgnored) {
            return areWarningsIgnored(Output.of(areWarningsIgnored));
        }

        /**
         * @param planExecutionType The type of the plan execution.
         * 
         * @return builder
         * 
         */
        public Builder planExecutionType(Output<String> planExecutionType) {
            $.planExecutionType = planExecutionType;
            return this;
        }

        /**
         * @param planExecutionType The type of the plan execution.
         * 
         * @return builder
         * 
         */
        public Builder planExecutionType(String planExecutionType) {
            return planExecutionType(Output.of(planExecutionType));
        }

        public DrPlanExecutionExecutionOptionsArgs build() {
            $.planExecutionType = Objects.requireNonNull($.planExecutionType, "expected parameter 'planExecutionType' to be non-null");
            return $;
        }
    }

}