// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BuildRunBuildOutputArtifactOverrideParameterItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildRunBuildOutputArtifactOverrideParameterItemArgs Empty = new BuildRunBuildOutputArtifactOverrideParameterItemArgs();

    /**
     * The OCID of the deployment artifact definition.
     * 
     */
    @Import(name="deployArtifactId")
    private @Nullable Output<String> deployArtifactId;

    /**
     * @return The OCID of the deployment artifact definition.
     * 
     */
    public Optional<Output<String>> deployArtifactId() {
        return Optional.ofNullable(this.deployArtifactId);
    }

    /**
     * Name of the step.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Name of the step.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Value of the argument.
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return Value of the argument.
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private BuildRunBuildOutputArtifactOverrideParameterItemArgs() {}

    private BuildRunBuildOutputArtifactOverrideParameterItemArgs(BuildRunBuildOutputArtifactOverrideParameterItemArgs $) {
        this.deployArtifactId = $.deployArtifactId;
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildRunBuildOutputArtifactOverrideParameterItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildRunBuildOutputArtifactOverrideParameterItemArgs $;

        public Builder() {
            $ = new BuildRunBuildOutputArtifactOverrideParameterItemArgs();
        }

        public Builder(BuildRunBuildOutputArtifactOverrideParameterItemArgs defaults) {
            $ = new BuildRunBuildOutputArtifactOverrideParameterItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param deployArtifactId The OCID of the deployment artifact definition.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactId(@Nullable Output<String> deployArtifactId) {
            $.deployArtifactId = deployArtifactId;
            return this;
        }

        /**
         * @param deployArtifactId The OCID of the deployment artifact definition.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactId(String deployArtifactId) {
            return deployArtifactId(Output.of(deployArtifactId));
        }

        /**
         * @param name Name of the step.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name of the step.
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
        public Builder value(@Nullable Output<String> value) {
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

        public BuildRunBuildOutputArtifactOverrideParameterItemArgs build() {
            return $;
        }
    }

}
