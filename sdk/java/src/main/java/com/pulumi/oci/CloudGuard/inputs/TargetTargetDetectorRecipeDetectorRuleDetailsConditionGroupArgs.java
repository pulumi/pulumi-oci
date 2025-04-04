// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs Empty = new TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs();

    /**
     * (Updatable) Compartment OCID associated with condition
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment OCID associated with condition
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) The base condition resource.
     * 
     */
    @Import(name="condition", required=true)
    private Output<String> condition;

    /**
     * @return (Updatable) The base condition resource.
     * 
     */
    public Output<String> condition() {
        return this.condition;
    }

    private TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs() {}

    private TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs(TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs $) {
        this.compartmentId = $.compartmentId;
        this.condition = $.condition;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs $;

        public Builder() {
            $ = new TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs();
        }

        public Builder(TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs defaults) {
            $ = new TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment OCID associated with condition
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment OCID associated with condition
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param condition (Updatable) The base condition resource.
         * 
         * @return builder
         * 
         */
        public Builder condition(Output<String> condition) {
            $.condition = condition;
            return this;
        }

        /**
         * @param condition (Updatable) The base condition resource.
         * 
         * @return builder
         * 
         */
        public Builder condition(String condition) {
            return condition(Output.of(condition));
        }

        public TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs", "compartmentId");
            }
            if ($.condition == null) {
                throw new MissingRequiredPropertyException("TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupArgs", "condition");
            }
            return $;
        }
    }

}
