// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class BuildRunBuildRunArgumentsItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildRunBuildRunArgumentsItemArgs Empty = new BuildRunBuildRunArgumentsItemArgs();

    /**
     * Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * Value of the argument.
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return Value of the argument.
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private BuildRunBuildRunArgumentsItemArgs() {}

    private BuildRunBuildRunArgumentsItemArgs(BuildRunBuildRunArgumentsItemArgs $) {
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildRunBuildRunArgumentsItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildRunBuildRunArgumentsItemArgs $;

        public Builder() {
            $ = new BuildRunBuildRunArgumentsItemArgs();
        }

        public Builder(BuildRunBuildRunArgumentsItemArgs defaults) {
            $ = new BuildRunBuildRunArgumentsItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param value Value of the argument.
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value Value of the argument.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public BuildRunBuildRunArgumentsItemArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("BuildRunBuildRunArgumentsItemArgs", "name");
            }
            if ($.value == null) {
                throw new MissingRequiredPropertyException("BuildRunBuildRunArgumentsItemArgs", "value");
            }
            return $;
        }
    }

}
