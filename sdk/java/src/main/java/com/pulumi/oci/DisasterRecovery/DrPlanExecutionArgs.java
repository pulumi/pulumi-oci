// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DisasterRecovery.inputs.DrPlanExecutionExecutionOptionsArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrPlanExecutionArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrPlanExecutionArgs Empty = new DrPlanExecutionArgs();

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The options for a plan execution.
     * 
     */
    @Import(name="executionOptions", required=true)
    private Output<DrPlanExecutionExecutionOptionsArgs> executionOptions;

    /**
     * @return The options for a plan execution.
     * 
     */
    public Output<DrPlanExecutionExecutionOptionsArgs> executionOptions() {
        return this.executionOptions;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="planId", required=true)
    private Output<String> planId;

    /**
     * @return The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> planId() {
        return this.planId;
    }

    private DrPlanExecutionArgs() {}

    private DrPlanExecutionArgs(DrPlanExecutionArgs $) {
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.executionOptions = $.executionOptions;
        this.freeformTags = $.freeformTags;
        this.planId = $.planId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrPlanExecutionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrPlanExecutionArgs $;

        public Builder() {
            $ = new DrPlanExecutionArgs();
        }

        public Builder(DrPlanExecutionArgs defaults) {
            $ = new DrPlanExecutionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param executionOptions The options for a plan execution.
         * 
         * @return builder
         * 
         */
        public Builder executionOptions(Output<DrPlanExecutionExecutionOptionsArgs> executionOptions) {
            $.executionOptions = executionOptions;
            return this;
        }

        /**
         * @param executionOptions The options for a plan execution.
         * 
         * @return builder
         * 
         */
        public Builder executionOptions(DrPlanExecutionExecutionOptionsArgs executionOptions) {
            return executionOptions(Output.of(executionOptions));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param planId The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder planId(Output<String> planId) {
            $.planId = planId;
            return this;
        }

        /**
         * @param planId The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder planId(String planId) {
            return planId(Output.of(planId));
        }

        public DrPlanExecutionArgs build() {
            if ($.executionOptions == null) {
                throw new MissingRequiredPropertyException("DrPlanExecutionArgs", "executionOptions");
            }
            if ($.planId == null) {
                throw new MissingRequiredPropertyException("DrPlanExecutionArgs", "planId");
            }
            return $;
        }
    }

}
