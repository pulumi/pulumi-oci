// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.BuildRunBuildOutputArtifactOverrideParameterItemArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BuildRunBuildOutputArtifactOverrideParameterArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildRunBuildOutputArtifactOverrideParameterArgs Empty = new BuildRunBuildOutputArtifactOverrideParameterArgs();

    /**
     * List of exported variables.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<BuildRunBuildOutputArtifactOverrideParameterItemArgs>> items;

    /**
     * @return List of exported variables.
     * 
     */
    public Optional<Output<List<BuildRunBuildOutputArtifactOverrideParameterItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    private BuildRunBuildOutputArtifactOverrideParameterArgs() {}

    private BuildRunBuildOutputArtifactOverrideParameterArgs(BuildRunBuildOutputArtifactOverrideParameterArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildRunBuildOutputArtifactOverrideParameterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildRunBuildOutputArtifactOverrideParameterArgs $;

        public Builder() {
            $ = new BuildRunBuildOutputArtifactOverrideParameterArgs();
        }

        public Builder(BuildRunBuildOutputArtifactOverrideParameterArgs defaults) {
            $ = new BuildRunBuildOutputArtifactOverrideParameterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items List of exported variables.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<BuildRunBuildOutputArtifactOverrideParameterItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items List of exported variables.
         * 
         * @return builder
         * 
         */
        public Builder items(List<BuildRunBuildOutputArtifactOverrideParameterItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items List of exported variables.
         * 
         * @return builder
         * 
         */
        public Builder items(BuildRunBuildOutputArtifactOverrideParameterItemArgs... items) {
            return items(List.of(items));
        }

        public BuildRunBuildOutputArtifactOverrideParameterArgs build() {
            return $;
        }
    }

}
