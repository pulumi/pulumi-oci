// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.inputs.NamespaceIngestTimeRuleConditionsAdditionalConditionArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NamespaceIngestTimeRuleConditionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final NamespaceIngestTimeRuleConditionsArgs Empty = new NamespaceIngestTimeRuleConditionsArgs();

    /**
     * (Updatable) Optional additional condition(s) to be evaluated.
     * 
     */
    @Import(name="additionalConditions")
    private @Nullable Output<List<NamespaceIngestTimeRuleConditionsAdditionalConditionArgs>> additionalConditions;

    /**
     * @return (Updatable) Optional additional condition(s) to be evaluated.
     * 
     */
    public Optional<Output<List<NamespaceIngestTimeRuleConditionsAdditionalConditionArgs>>> additionalConditions() {
        return Optional.ofNullable(this.additionalConditions);
    }

    /**
     * (Updatable) The field name to be evaluated.
     * 
     */
    @Import(name="fieldName", required=true)
    private Output<String> fieldName;

    /**
     * @return (Updatable) The field name to be evaluated.
     * 
     */
    public Output<String> fieldName() {
        return this.fieldName;
    }

    /**
     * (Updatable) The operator to be used for evaluating the field.
     * 
     */
    @Import(name="fieldOperator", required=true)
    private Output<String> fieldOperator;

    /**
     * @return (Updatable) The operator to be used for evaluating the field.
     * 
     */
    public Output<String> fieldOperator() {
        return this.fieldOperator;
    }

    /**
     * (Updatable) The field value to be evaluated.
     * 
     */
    @Import(name="fieldValue", required=true)
    private Output<String> fieldValue;

    /**
     * @return (Updatable) The field value to be evaluated.
     * 
     */
    public Output<String> fieldValue() {
        return this.fieldValue;
    }

    /**
     * (Updatable) Discriminator.
     * 
     */
    @Import(name="kind", required=true)
    private Output<String> kind;

    /**
     * @return (Updatable) Discriminator.
     * 
     */
    public Output<String> kind() {
        return this.kind;
    }

    private NamespaceIngestTimeRuleConditionsArgs() {}

    private NamespaceIngestTimeRuleConditionsArgs(NamespaceIngestTimeRuleConditionsArgs $) {
        this.additionalConditions = $.additionalConditions;
        this.fieldName = $.fieldName;
        this.fieldOperator = $.fieldOperator;
        this.fieldValue = $.fieldValue;
        this.kind = $.kind;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NamespaceIngestTimeRuleConditionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NamespaceIngestTimeRuleConditionsArgs $;

        public Builder() {
            $ = new NamespaceIngestTimeRuleConditionsArgs();
        }

        public Builder(NamespaceIngestTimeRuleConditionsArgs defaults) {
            $ = new NamespaceIngestTimeRuleConditionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param additionalConditions (Updatable) Optional additional condition(s) to be evaluated.
         * 
         * @return builder
         * 
         */
        public Builder additionalConditions(@Nullable Output<List<NamespaceIngestTimeRuleConditionsAdditionalConditionArgs>> additionalConditions) {
            $.additionalConditions = additionalConditions;
            return this;
        }

        /**
         * @param additionalConditions (Updatable) Optional additional condition(s) to be evaluated.
         * 
         * @return builder
         * 
         */
        public Builder additionalConditions(List<NamespaceIngestTimeRuleConditionsAdditionalConditionArgs> additionalConditions) {
            return additionalConditions(Output.of(additionalConditions));
        }

        /**
         * @param additionalConditions (Updatable) Optional additional condition(s) to be evaluated.
         * 
         * @return builder
         * 
         */
        public Builder additionalConditions(NamespaceIngestTimeRuleConditionsAdditionalConditionArgs... additionalConditions) {
            return additionalConditions(List.of(additionalConditions));
        }

        /**
         * @param fieldName (Updatable) The field name to be evaluated.
         * 
         * @return builder
         * 
         */
        public Builder fieldName(Output<String> fieldName) {
            $.fieldName = fieldName;
            return this;
        }

        /**
         * @param fieldName (Updatable) The field name to be evaluated.
         * 
         * @return builder
         * 
         */
        public Builder fieldName(String fieldName) {
            return fieldName(Output.of(fieldName));
        }

        /**
         * @param fieldOperator (Updatable) The operator to be used for evaluating the field.
         * 
         * @return builder
         * 
         */
        public Builder fieldOperator(Output<String> fieldOperator) {
            $.fieldOperator = fieldOperator;
            return this;
        }

        /**
         * @param fieldOperator (Updatable) The operator to be used for evaluating the field.
         * 
         * @return builder
         * 
         */
        public Builder fieldOperator(String fieldOperator) {
            return fieldOperator(Output.of(fieldOperator));
        }

        /**
         * @param fieldValue (Updatable) The field value to be evaluated.
         * 
         * @return builder
         * 
         */
        public Builder fieldValue(Output<String> fieldValue) {
            $.fieldValue = fieldValue;
            return this;
        }

        /**
         * @param fieldValue (Updatable) The field value to be evaluated.
         * 
         * @return builder
         * 
         */
        public Builder fieldValue(String fieldValue) {
            return fieldValue(Output.of(fieldValue));
        }

        /**
         * @param kind (Updatable) Discriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(Output<String> kind) {
            $.kind = kind;
            return this;
        }

        /**
         * @param kind (Updatable) Discriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(String kind) {
            return kind(Output.of(kind));
        }

        public NamespaceIngestTimeRuleConditionsArgs build() {
            if ($.fieldName == null) {
                throw new MissingRequiredPropertyException("NamespaceIngestTimeRuleConditionsArgs", "fieldName");
            }
            if ($.fieldOperator == null) {
                throw new MissingRequiredPropertyException("NamespaceIngestTimeRuleConditionsArgs", "fieldOperator");
            }
            if ($.fieldValue == null) {
                throw new MissingRequiredPropertyException("NamespaceIngestTimeRuleConditionsArgs", "fieldValue");
            }
            if ($.kind == null) {
                throw new MissingRequiredPropertyException("NamespaceIngestTimeRuleConditionsArgs", "kind");
            }
            return $;
        }
    }

}
