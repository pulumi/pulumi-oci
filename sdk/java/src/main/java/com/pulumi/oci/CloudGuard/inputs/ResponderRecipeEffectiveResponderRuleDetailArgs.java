// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudGuard.inputs.ResponderRecipeEffectiveResponderRuleDetailConfigurationArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ResponderRecipeEffectiveResponderRuleDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final ResponderRecipeEffectiveResponderRuleDetailArgs Empty = new ResponderRecipeEffectiveResponderRuleDetailArgs();

    /**
     * Base condition object
     * 
     */
    @Import(name="condition")
    private @Nullable Output<String> condition;

    /**
     * @return Base condition object
     * 
     */
    public Optional<Output<String>> condition() {
        return Optional.ofNullable(this.condition);
    }

    /**
     * ResponderRule configurations
     * 
     */
    @Import(name="configurations")
    private @Nullable Output<List<ResponderRecipeEffectiveResponderRuleDetailConfigurationArgs>> configurations;

    /**
     * @return ResponderRule configurations
     * 
     */
    public Optional<Output<List<ResponderRecipeEffectiveResponderRuleDetailConfigurationArgs>>> configurations() {
        return Optional.ofNullable(this.configurations);
    }

    /**
     * (Updatable) Identifies state for ResponderRule
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Identifies state for ResponderRule
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * Execution Mode for ResponderRule
     * 
     */
    @Import(name="mode")
    private @Nullable Output<String> mode;

    /**
     * @return Execution Mode for ResponderRule
     * 
     */
    public Optional<Output<String>> mode() {
        return Optional.ofNullable(this.mode);
    }

    private ResponderRecipeEffectiveResponderRuleDetailArgs() {}

    private ResponderRecipeEffectiveResponderRuleDetailArgs(ResponderRecipeEffectiveResponderRuleDetailArgs $) {
        this.condition = $.condition;
        this.configurations = $.configurations;
        this.isEnabled = $.isEnabled;
        this.mode = $.mode;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ResponderRecipeEffectiveResponderRuleDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ResponderRecipeEffectiveResponderRuleDetailArgs $;

        public Builder() {
            $ = new ResponderRecipeEffectiveResponderRuleDetailArgs();
        }

        public Builder(ResponderRecipeEffectiveResponderRuleDetailArgs defaults) {
            $ = new ResponderRecipeEffectiveResponderRuleDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param condition Base condition object
         * 
         * @return builder
         * 
         */
        public Builder condition(@Nullable Output<String> condition) {
            $.condition = condition;
            return this;
        }

        /**
         * @param condition Base condition object
         * 
         * @return builder
         * 
         */
        public Builder condition(String condition) {
            return condition(Output.of(condition));
        }

        /**
         * @param configurations ResponderRule configurations
         * 
         * @return builder
         * 
         */
        public Builder configurations(@Nullable Output<List<ResponderRecipeEffectiveResponderRuleDetailConfigurationArgs>> configurations) {
            $.configurations = configurations;
            return this;
        }

        /**
         * @param configurations ResponderRule configurations
         * 
         * @return builder
         * 
         */
        public Builder configurations(List<ResponderRecipeEffectiveResponderRuleDetailConfigurationArgs> configurations) {
            return configurations(Output.of(configurations));
        }

        /**
         * @param configurations ResponderRule configurations
         * 
         * @return builder
         * 
         */
        public Builder configurations(ResponderRecipeEffectiveResponderRuleDetailConfigurationArgs... configurations) {
            return configurations(List.of(configurations));
        }

        /**
         * @param isEnabled (Updatable) Identifies state for ResponderRule
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Identifies state for ResponderRule
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param mode Execution Mode for ResponderRule
         * 
         * @return builder
         * 
         */
        public Builder mode(@Nullable Output<String> mode) {
            $.mode = mode;
            return this;
        }

        /**
         * @param mode Execution Mode for ResponderRule
         * 
         * @return builder
         * 
         */
        public Builder mode(String mode) {
            return mode(Output.of(mode));
        }

        public ResponderRecipeEffectiveResponderRuleDetailArgs build() {
            return $;
        }
    }

}