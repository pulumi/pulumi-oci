// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class BuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter {
    /**
     * @return The file paths/glob pattern for files.
     * 
     */
    private @Nullable List<String> filePaths;

    private BuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter() {}
    /**
     * @return The file paths/glob pattern for files.
     * 
     */
    public List<String> filePaths() {
        return this.filePaths == null ? List.of() : this.filePaths;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> filePaths;
        public Builder() {}
        public Builder(BuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filePaths = defaults.filePaths;
        }

        @CustomType.Setter
        public Builder filePaths(@Nullable List<String> filePaths) {

            this.filePaths = filePaths;
            return this;
        }
        public Builder filePaths(String... filePaths) {
            return filePaths(List.of(filePaths));
        }
        public BuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter build() {
            final var _resultValue = new BuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter();
            _resultValue.filePaths = filePaths;
            return _resultValue;
        }
    }
}
