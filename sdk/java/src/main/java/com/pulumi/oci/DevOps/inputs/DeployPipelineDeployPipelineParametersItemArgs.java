// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployPipelineDeployPipelineParametersItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployPipelineDeployPipelineParametersItemArgs Empty = new DeployPipelineDeployPipelineParametersItemArgs();

    /**
     * (Updatable) Default value of the parameter.
     * 
     */
    @Import(name="defaultValue")
    private @Nullable Output<String> defaultValue;

    /**
     * @return (Updatable) Default value of the parameter.
     * 
     */
    public Optional<Output<String>> defaultValue() {
        return Optional.ofNullable(this.defaultValue);
    }

    /**
     * (Updatable) Optional description about the deployment pipeline.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Optional description about the deployment pipeline.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    private DeployPipelineDeployPipelineParametersItemArgs() {}

    private DeployPipelineDeployPipelineParametersItemArgs(DeployPipelineDeployPipelineParametersItemArgs $) {
        this.defaultValue = $.defaultValue;
        this.description = $.description;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployPipelineDeployPipelineParametersItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployPipelineDeployPipelineParametersItemArgs $;

        public Builder() {
            $ = new DeployPipelineDeployPipelineParametersItemArgs();
        }

        public Builder(DeployPipelineDeployPipelineParametersItemArgs defaults) {
            $ = new DeployPipelineDeployPipelineParametersItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param defaultValue (Updatable) Default value of the parameter.
         * 
         * @return builder
         * 
         */
        public Builder defaultValue(@Nullable Output<String> defaultValue) {
            $.defaultValue = defaultValue;
            return this;
        }

        /**
         * @param defaultValue (Updatable) Default value of the parameter.
         * 
         * @return builder
         * 
         */
        public Builder defaultValue(String defaultValue) {
            return defaultValue(Output.of(defaultValue));
        }

        /**
         * @param description (Updatable) Optional description about the deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Optional description about the deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param name (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public DeployPipelineDeployPipelineParametersItemArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            return $;
        }
    }

}