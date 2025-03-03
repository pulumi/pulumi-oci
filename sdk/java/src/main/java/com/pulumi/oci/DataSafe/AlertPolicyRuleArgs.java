// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AlertPolicyRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final AlertPolicyRuleArgs Empty = new AlertPolicyRuleArgs();

    /**
     * The OCID of the alert policy.
     * 
     */
    @Import(name="alertPolicyId", required=true)
    private Output<String> alertPolicyId;

    /**
     * @return The OCID of the alert policy.
     * 
     */
    public Output<String> alertPolicyId() {
        return this.alertPolicyId;
    }

    /**
     * (Updatable) Describes the alert policy rule.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Describes the alert policy rule.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The display name of the alert policy rule.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The display name of the alert policy rule.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="expression", required=true)
    private Output<String> expression;

    /**
     * @return (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> expression() {
        return this.expression;
    }

    private AlertPolicyRuleArgs() {}

    private AlertPolicyRuleArgs(AlertPolicyRuleArgs $) {
        this.alertPolicyId = $.alertPolicyId;
        this.description = $.description;
        this.displayName = $.displayName;
        this.expression = $.expression;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AlertPolicyRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AlertPolicyRuleArgs $;

        public Builder() {
            $ = new AlertPolicyRuleArgs();
        }

        public Builder(AlertPolicyRuleArgs defaults) {
            $ = new AlertPolicyRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param alertPolicyId The OCID of the alert policy.
         * 
         * @return builder
         * 
         */
        public Builder alertPolicyId(Output<String> alertPolicyId) {
            $.alertPolicyId = alertPolicyId;
            return this;
        }

        /**
         * @param alertPolicyId The OCID of the alert policy.
         * 
         * @return builder
         * 
         */
        public Builder alertPolicyId(String alertPolicyId) {
            return alertPolicyId(Output.of(alertPolicyId));
        }

        /**
         * @param description (Updatable) Describes the alert policy rule.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Describes the alert policy rule.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) The display name of the alert policy rule.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the alert policy rule.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param expression (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder expression(Output<String> expression) {
            $.expression = expression;
            return this;
        }

        /**
         * @param expression (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder expression(String expression) {
            return expression(Output.of(expression));
        }

        public AlertPolicyRuleArgs build() {
            if ($.alertPolicyId == null) {
                throw new MissingRequiredPropertyException("AlertPolicyRuleArgs", "alertPolicyId");
            }
            if ($.expression == null) {
                throw new MissingRequiredPropertyException("AlertPolicyRuleArgs", "expression");
            }
            return $;
        }
    }

}
