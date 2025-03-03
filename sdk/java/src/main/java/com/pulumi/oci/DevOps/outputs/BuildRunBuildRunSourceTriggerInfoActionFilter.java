// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.BuildRunBuildRunSourceTriggerInfoActionFilterExclude;
import com.pulumi.oci.DevOps.outputs.BuildRunBuildRunSourceTriggerInfoActionFilterInclude;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BuildRunBuildRunSourceTriggerInfoActionFilter {
    /**
     * @return The events, for example, PUSH, PULL_REQUEST_CREATED, PULL_REQUEST_UPDATED.
     * 
     */
    private @Nullable List<String> events;
    /**
     * @return Attributes to filter GitLab self-hosted server events. File filter criteria - Changes only affecting excluded files will not invoke a build. if both include and exclude filter are used then exclusion filter will be applied on the result set of inclusion filter.
     * 
     */
    private @Nullable List<BuildRunBuildRunSourceTriggerInfoActionFilterExclude> excludes;
    /**
     * @return Attributes to filter GitLab self-hosted server events.
     * 
     */
    private @Nullable List<BuildRunBuildRunSourceTriggerInfoActionFilterInclude> includes;
    /**
     * @return Source of the trigger. Allowed values are, GITHUB and GITLAB.
     * 
     */
    private @Nullable String triggerSource;

    private BuildRunBuildRunSourceTriggerInfoActionFilter() {}
    /**
     * @return The events, for example, PUSH, PULL_REQUEST_CREATED, PULL_REQUEST_UPDATED.
     * 
     */
    public List<String> events() {
        return this.events == null ? List.of() : this.events;
    }
    /**
     * @return Attributes to filter GitLab self-hosted server events. File filter criteria - Changes only affecting excluded files will not invoke a build. if both include and exclude filter are used then exclusion filter will be applied on the result set of inclusion filter.
     * 
     */
    public List<BuildRunBuildRunSourceTriggerInfoActionFilterExclude> excludes() {
        return this.excludes == null ? List.of() : this.excludes;
    }
    /**
     * @return Attributes to filter GitLab self-hosted server events.
     * 
     */
    public List<BuildRunBuildRunSourceTriggerInfoActionFilterInclude> includes() {
        return this.includes == null ? List.of() : this.includes;
    }
    /**
     * @return Source of the trigger. Allowed values are, GITHUB and GITLAB.
     * 
     */
    public Optional<String> triggerSource() {
        return Optional.ofNullable(this.triggerSource);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BuildRunBuildRunSourceTriggerInfoActionFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> events;
        private @Nullable List<BuildRunBuildRunSourceTriggerInfoActionFilterExclude> excludes;
        private @Nullable List<BuildRunBuildRunSourceTriggerInfoActionFilterInclude> includes;
        private @Nullable String triggerSource;
        public Builder() {}
        public Builder(BuildRunBuildRunSourceTriggerInfoActionFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.events = defaults.events;
    	      this.excludes = defaults.excludes;
    	      this.includes = defaults.includes;
    	      this.triggerSource = defaults.triggerSource;
        }

        @CustomType.Setter
        public Builder events(@Nullable List<String> events) {

            this.events = events;
            return this;
        }
        public Builder events(String... events) {
            return events(List.of(events));
        }
        @CustomType.Setter
        public Builder excludes(@Nullable List<BuildRunBuildRunSourceTriggerInfoActionFilterExclude> excludes) {

            this.excludes = excludes;
            return this;
        }
        public Builder excludes(BuildRunBuildRunSourceTriggerInfoActionFilterExclude... excludes) {
            return excludes(List.of(excludes));
        }
        @CustomType.Setter
        public Builder includes(@Nullable List<BuildRunBuildRunSourceTriggerInfoActionFilterInclude> includes) {

            this.includes = includes;
            return this;
        }
        public Builder includes(BuildRunBuildRunSourceTriggerInfoActionFilterInclude... includes) {
            return includes(List.of(includes));
        }
        @CustomType.Setter
        public Builder triggerSource(@Nullable String triggerSource) {

            this.triggerSource = triggerSource;
            return this;
        }
        public BuildRunBuildRunSourceTriggerInfoActionFilter build() {
            final var _resultValue = new BuildRunBuildRunSourceTriggerInfoActionFilter();
            _resultValue.events = events;
            _resultValue.excludes = excludes;
            _resultValue.includes = includes;
            _resultValue.triggerSource = triggerSource;
            return _resultValue;
        }
    }
}
