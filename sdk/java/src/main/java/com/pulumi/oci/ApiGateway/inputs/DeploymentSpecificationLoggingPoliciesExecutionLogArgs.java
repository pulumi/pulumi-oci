// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentSpecificationLoggingPoliciesExecutionLogArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationLoggingPoliciesExecutionLogArgs Empty = new DeploymentSpecificationLoggingPoliciesExecutionLogArgs();

    /**
     * (Updatable) Whether this policy is currently enabled.
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Whether this policy is currently enabled.
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * (Updatable) Specifies the log level used to control logging output of execution logs. Enabling logging at a given level also enables logging at all higher levels.
     * 
     */
    @Import(name="logLevel")
    private @Nullable Output<String> logLevel;

    /**
     * @return (Updatable) Specifies the log level used to control logging output of execution logs. Enabling logging at a given level also enables logging at all higher levels.
     * 
     */
    public Optional<Output<String>> logLevel() {
        return Optional.ofNullable(this.logLevel);
    }

    private DeploymentSpecificationLoggingPoliciesExecutionLogArgs() {}

    private DeploymentSpecificationLoggingPoliciesExecutionLogArgs(DeploymentSpecificationLoggingPoliciesExecutionLogArgs $) {
        this.isEnabled = $.isEnabled;
        this.logLevel = $.logLevel;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationLoggingPoliciesExecutionLogArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationLoggingPoliciesExecutionLogArgs $;

        public Builder() {
            $ = new DeploymentSpecificationLoggingPoliciesExecutionLogArgs();
        }

        public Builder(DeploymentSpecificationLoggingPoliciesExecutionLogArgs defaults) {
            $ = new DeploymentSpecificationLoggingPoliciesExecutionLogArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isEnabled (Updatable) Whether this policy is currently enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Whether this policy is currently enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param logLevel (Updatable) Specifies the log level used to control logging output of execution logs. Enabling logging at a given level also enables logging at all higher levels.
         * 
         * @return builder
         * 
         */
        public Builder logLevel(@Nullable Output<String> logLevel) {
            $.logLevel = logLevel;
            return this;
        }

        /**
         * @param logLevel (Updatable) Specifies the log level used to control logging output of execution logs. Enabling logging at a given level also enables logging at all higher levels.
         * 
         * @return builder
         * 
         */
        public Builder logLevel(String logLevel) {
            return logLevel(Output.of(logLevel));
        }

        public DeploymentSpecificationLoggingPoliciesExecutionLogArgs build() {
            return $;
        }
    }

}