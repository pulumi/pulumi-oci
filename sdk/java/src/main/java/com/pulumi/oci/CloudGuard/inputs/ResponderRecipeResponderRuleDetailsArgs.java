// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.inputs.ResponderRecipeResponderRuleDetailsConfigurationArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ResponderRecipeResponderRuleDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ResponderRecipeResponderRuleDetailsArgs Empty = new ResponderRecipeResponderRuleDetailsArgs();

    /**
     * The base condition resource.
     * 
     */
    @Import(name="condition")
    private @Nullable Output<String> condition;

    /**
     * @return The base condition resource.
     * 
     */
    public Optional<Output<String>> condition() {
        return Optional.ofNullable(this.condition);
    }

    /**
     * List of responder rule configurations
     * 
     */
    @Import(name="configurations")
    private @Nullable Output<List<ResponderRecipeResponderRuleDetailsConfigurationArgs>> configurations;

    /**
     * @return List of responder rule configurations
     * 
     */
    public Optional<Output<List<ResponderRecipeResponderRuleDetailsConfigurationArgs>>> configurations() {
        return Optional.ofNullable(this.configurations);
    }

    /**
     * (Updatable) Enablement state for the responder rule
     * 
     */
    @Import(name="isEnabled", required=true)
    private Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Enablement state for the responder rule
     * 
     */
    public Output<Boolean> isEnabled() {
        return this.isEnabled;
    }

    /**
     * Execution mode for the responder rule
     * 
     */
    @Import(name="mode")
    private @Nullable Output<String> mode;

    /**
     * @return Execution mode for the responder rule
     * 
     */
    public Optional<Output<String>> mode() {
        return Optional.ofNullable(this.mode);
    }

    private ResponderRecipeResponderRuleDetailsArgs() {}

    private ResponderRecipeResponderRuleDetailsArgs(ResponderRecipeResponderRuleDetailsArgs $) {
        this.condition = $.condition;
        this.configurations = $.configurations;
        this.isEnabled = $.isEnabled;
        this.mode = $.mode;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ResponderRecipeResponderRuleDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ResponderRecipeResponderRuleDetailsArgs $;

        public Builder() {
            $ = new ResponderRecipeResponderRuleDetailsArgs();
        }

        public Builder(ResponderRecipeResponderRuleDetailsArgs defaults) {
            $ = new ResponderRecipeResponderRuleDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param condition The base condition resource.
         * 
         * @return builder
         * 
         */
        public Builder condition(@Nullable Output<String> condition) {
            $.condition = condition;
            return this;
        }

        /**
         * @param condition The base condition resource.
         * 
         * @return builder
         * 
         */
        public Builder condition(String condition) {
            return condition(Output.of(condition));
        }

        /**
         * @param configurations List of responder rule configurations
         * 
         * @return builder
         * 
         */
        public Builder configurations(@Nullable Output<List<ResponderRecipeResponderRuleDetailsConfigurationArgs>> configurations) {
            $.configurations = configurations;
            return this;
        }

        /**
         * @param configurations List of responder rule configurations
         * 
         * @return builder
         * 
         */
        public Builder configurations(List<ResponderRecipeResponderRuleDetailsConfigurationArgs> configurations) {
            return configurations(Output.of(configurations));
        }

        /**
         * @param configurations List of responder rule configurations
         * 
         * @return builder
         * 
         */
        public Builder configurations(ResponderRecipeResponderRuleDetailsConfigurationArgs... configurations) {
            return configurations(List.of(configurations));
        }

        /**
         * @param isEnabled (Updatable) Enablement state for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Enablement state for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param mode Execution mode for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder mode(@Nullable Output<String> mode) {
            $.mode = mode;
            return this;
        }

        /**
         * @param mode Execution mode for the responder rule
         * 
         * @return builder
         * 
         */
        public Builder mode(String mode) {
            return mode(Output.of(mode));
        }

        public ResponderRecipeResponderRuleDetailsArgs build() {
            if ($.isEnabled == null) {
                throw new MissingRequiredPropertyException("ResponderRecipeResponderRuleDetailsArgs", "isEnabled");
            }
            return $;
        }
    }

}
