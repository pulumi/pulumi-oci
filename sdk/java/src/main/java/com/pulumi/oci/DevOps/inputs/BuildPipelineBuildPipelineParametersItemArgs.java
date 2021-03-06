// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BuildPipelineBuildPipelineParametersItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildPipelineBuildPipelineParametersItemArgs Empty = new BuildPipelineBuildPipelineParametersItemArgs();

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
     * (Updatable) Optional description about the build pipeline.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Optional description about the build pipeline.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    private BuildPipelineBuildPipelineParametersItemArgs() {}

    private BuildPipelineBuildPipelineParametersItemArgs(BuildPipelineBuildPipelineParametersItemArgs $) {
        this.defaultValue = $.defaultValue;
        this.description = $.description;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildPipelineBuildPipelineParametersItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildPipelineBuildPipelineParametersItemArgs $;

        public Builder() {
            $ = new BuildPipelineBuildPipelineParametersItemArgs();
        }

        public Builder(BuildPipelineBuildPipelineParametersItemArgs defaults) {
            $ = new BuildPipelineBuildPipelineParametersItemArgs(Objects.requireNonNull(defaults));
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
         * @param description (Updatable) Optional description about the build pipeline.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Optional description about the build pipeline.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param name (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public BuildPipelineBuildPipelineParametersItemArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            return $;
        }
    }

}
