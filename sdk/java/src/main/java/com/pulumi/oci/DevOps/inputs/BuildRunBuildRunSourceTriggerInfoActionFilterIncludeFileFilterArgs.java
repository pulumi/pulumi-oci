// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs Empty = new BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs();

    @Import(name="filePaths")
    private @Nullable Output<List<String>> filePaths;

    public Optional<Output<List<String>>> filePaths() {
        return Optional.ofNullable(this.filePaths);
    }

    private BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs() {}

    private BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs(BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs $) {
        this.filePaths = $.filePaths;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs $;

        public Builder() {
            $ = new BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs();
        }

        public Builder(BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs defaults) {
            $ = new BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs(Objects.requireNonNull(defaults));
        }

        public Builder filePaths(@Nullable Output<List<String>> filePaths) {
            $.filePaths = filePaths;
            return this;
        }

        public Builder filePaths(List<String> filePaths) {
            return filePaths(Output.of(filePaths));
        }

        public Builder filePaths(String... filePaths) {
            return filePaths(List.of(filePaths));
        }

        public BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs build() {
            return $;
        }
    }

}