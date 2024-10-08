// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BuildPipelineStageBuildRunnerShapeConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildPipelineStageBuildRunnerShapeConfigArgs Empty = new BuildPipelineStageBuildRunnerShapeConfigArgs();

    /**
     * (Updatable) Name of the build runner shape in which the execution occurs. If not specified, the default shape is chosen.
     * 
     */
    @Import(name="buildRunnerType", required=true)
    private Output<String> buildRunnerType;

    /**
     * @return (Updatable) Name of the build runner shape in which the execution occurs. If not specified, the default shape is chosen.
     * 
     */
    public Output<String> buildRunnerType() {
        return this.buildRunnerType;
    }

    /**
     * (Updatable) The total amount of memory set for the instance in gigabytes.
     * 
     */
    @Import(name="memoryInGbs")
    private @Nullable Output<Integer> memoryInGbs;

    /**
     * @return (Updatable) The total amount of memory set for the instance in gigabytes.
     * 
     */
    public Optional<Output<Integer>> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }

    /**
     * (Updatable) The total number of OCPUs set for the instance.
     * 
     */
    @Import(name="ocpus")
    private @Nullable Output<Integer> ocpus;

    /**
     * @return (Updatable) The total number of OCPUs set for the instance.
     * 
     */
    public Optional<Output<Integer>> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }

    private BuildPipelineStageBuildRunnerShapeConfigArgs() {}

    private BuildPipelineStageBuildRunnerShapeConfigArgs(BuildPipelineStageBuildRunnerShapeConfigArgs $) {
        this.buildRunnerType = $.buildRunnerType;
        this.memoryInGbs = $.memoryInGbs;
        this.ocpus = $.ocpus;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildPipelineStageBuildRunnerShapeConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildPipelineStageBuildRunnerShapeConfigArgs $;

        public Builder() {
            $ = new BuildPipelineStageBuildRunnerShapeConfigArgs();
        }

        public Builder(BuildPipelineStageBuildRunnerShapeConfigArgs defaults) {
            $ = new BuildPipelineStageBuildRunnerShapeConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param buildRunnerType (Updatable) Name of the build runner shape in which the execution occurs. If not specified, the default shape is chosen.
         * 
         * @return builder
         * 
         */
        public Builder buildRunnerType(Output<String> buildRunnerType) {
            $.buildRunnerType = buildRunnerType;
            return this;
        }

        /**
         * @param buildRunnerType (Updatable) Name of the build runner shape in which the execution occurs. If not specified, the default shape is chosen.
         * 
         * @return builder
         * 
         */
        public Builder buildRunnerType(String buildRunnerType) {
            return buildRunnerType(Output.of(buildRunnerType));
        }

        /**
         * @param memoryInGbs (Updatable) The total amount of memory set for the instance in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(@Nullable Output<Integer> memoryInGbs) {
            $.memoryInGbs = memoryInGbs;
            return this;
        }

        /**
         * @param memoryInGbs (Updatable) The total amount of memory set for the instance in gigabytes.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(Integer memoryInGbs) {
            return memoryInGbs(Output.of(memoryInGbs));
        }

        /**
         * @param ocpus (Updatable) The total number of OCPUs set for the instance.
         * 
         * @return builder
         * 
         */
        public Builder ocpus(@Nullable Output<Integer> ocpus) {
            $.ocpus = ocpus;
            return this;
        }

        /**
         * @param ocpus (Updatable) The total number of OCPUs set for the instance.
         * 
         * @return builder
         * 
         */
        public Builder ocpus(Integer ocpus) {
            return ocpus(Output.of(ocpus));
        }

        public BuildPipelineStageBuildRunnerShapeConfigArgs build() {
            if ($.buildRunnerType == null) {
                throw new MissingRequiredPropertyException("BuildPipelineStageBuildRunnerShapeConfigArgs", "buildRunnerType");
            }
            return $;
        }
    }

}
