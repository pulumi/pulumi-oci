// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs Empty = new BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs();

    /**
     * The target branch for pull requests; not applicable for push requests.
     * 
     */
    @Import(name="baseRef")
    private @Nullable Output<String> baseRef;

    /**
     * @return The target branch for pull requests; not applicable for push requests.
     * 
     */
    public Optional<Output<String>> baseRef() {
        return Optional.ofNullable(this.baseRef);
    }

    /**
     * Attributes to support include/exclude files for triggering build runs.
     * 
     */
    @Import(name="fileFilters")
    private @Nullable Output<List<BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs>> fileFilters;

    /**
     * @return Attributes to support include/exclude files for triggering build runs.
     * 
     */
    public Optional<Output<List<BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs>>> fileFilters() {
        return Optional.ofNullable(this.fileFilters);
    }

    /**
     * Branch for push event; source branch for pull requests.
     * 
     */
    @Import(name="headRef")
    private @Nullable Output<String> headRef;

    /**
     * @return Branch for push event; source branch for pull requests.
     * 
     */
    public Optional<Output<String>> headRef() {
        return Optional.ofNullable(this.headRef);
    }

    /**
     * The repository name for trigger events.
     * 
     */
    @Import(name="repositoryName")
    private @Nullable Output<String> repositoryName;

    /**
     * @return The repository name for trigger events.
     * 
     */
    public Optional<Output<String>> repositoryName() {
        return Optional.ofNullable(this.repositoryName);
    }

    private BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs() {}

    private BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs(BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs $) {
        this.baseRef = $.baseRef;
        this.fileFilters = $.fileFilters;
        this.headRef = $.headRef;
        this.repositoryName = $.repositoryName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs $;

        public Builder() {
            $ = new BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs();
        }

        public Builder(BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs defaults) {
            $ = new BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param baseRef The target branch for pull requests; not applicable for push requests.
         * 
         * @return builder
         * 
         */
        public Builder baseRef(@Nullable Output<String> baseRef) {
            $.baseRef = baseRef;
            return this;
        }

        /**
         * @param baseRef The target branch for pull requests; not applicable for push requests.
         * 
         * @return builder
         * 
         */
        public Builder baseRef(String baseRef) {
            return baseRef(Output.of(baseRef));
        }

        /**
         * @param fileFilters Attributes to support include/exclude files for triggering build runs.
         * 
         * @return builder
         * 
         */
        public Builder fileFilters(@Nullable Output<List<BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs>> fileFilters) {
            $.fileFilters = fileFilters;
            return this;
        }

        /**
         * @param fileFilters Attributes to support include/exclude files for triggering build runs.
         * 
         * @return builder
         * 
         */
        public Builder fileFilters(List<BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs> fileFilters) {
            return fileFilters(Output.of(fileFilters));
        }

        /**
         * @param fileFilters Attributes to support include/exclude files for triggering build runs.
         * 
         * @return builder
         * 
         */
        public Builder fileFilters(BuildRunBuildRunSourceTriggerInfoActionFilterIncludeFileFilterArgs... fileFilters) {
            return fileFilters(List.of(fileFilters));
        }

        /**
         * @param headRef Branch for push event; source branch for pull requests.
         * 
         * @return builder
         * 
         */
        public Builder headRef(@Nullable Output<String> headRef) {
            $.headRef = headRef;
            return this;
        }

        /**
         * @param headRef Branch for push event; source branch for pull requests.
         * 
         * @return builder
         * 
         */
        public Builder headRef(String headRef) {
            return headRef(Output.of(headRef));
        }

        /**
         * @param repositoryName The repository name for trigger events.
         * 
         * @return builder
         * 
         */
        public Builder repositoryName(@Nullable Output<String> repositoryName) {
            $.repositoryName = repositoryName;
            return this;
        }

        /**
         * @param repositoryName The repository name for trigger events.
         * 
         * @return builder
         * 
         */
        public Builder repositoryName(String repositoryName) {
            return repositoryName(Output.of(repositoryName));
        }

        public BuildRunBuildRunSourceTriggerInfoActionFilterIncludeArgs build() {
            return $;
        }
    }

}
