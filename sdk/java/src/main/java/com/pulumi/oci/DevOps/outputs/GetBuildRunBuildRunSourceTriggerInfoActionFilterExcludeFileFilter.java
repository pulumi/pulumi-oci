// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter {
    private List<String> filePaths;

    private GetBuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter() {}
    public List<String> filePaths() {
        return this.filePaths;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> filePaths;
        public Builder() {}
        public Builder(GetBuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filePaths = defaults.filePaths;
        }

        @CustomType.Setter
        public Builder filePaths(List<String> filePaths) {
            this.filePaths = Objects.requireNonNull(filePaths);
            return this;
        }
        public Builder filePaths(String... filePaths) {
            return filePaths(List.of(filePaths));
        }
        public GetBuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter build() {
            final var o = new GetBuildRunBuildRunSourceTriggerInfoActionFilterExcludeFileFilter();
            o.filePaths = filePaths;
            return o;
        }
    }
}