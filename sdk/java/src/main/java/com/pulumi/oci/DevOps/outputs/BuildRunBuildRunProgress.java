// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BuildRunBuildRunProgress {
    /**
     * @return Map of stage OCIDs to build pipeline stage run progress model.
     * 
     */
    private @Nullable Map<String,Object> buildPipelineStageRunProgress;
    /**
     * @return The time the build run finished. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private @Nullable String timeFinished;
    /**
     * @return The time the build run started. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private @Nullable String timeStarted;

    private BuildRunBuildRunProgress() {}
    /**
     * @return Map of stage OCIDs to build pipeline stage run progress model.
     * 
     */
    public Map<String,Object> buildPipelineStageRunProgress() {
        return this.buildPipelineStageRunProgress == null ? Map.of() : this.buildPipelineStageRunProgress;
    }
    /**
     * @return The time the build run finished. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Optional<String> timeFinished() {
        return Optional.ofNullable(this.timeFinished);
    }
    /**
     * @return The time the build run started. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Optional<String> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BuildRunBuildRunProgress defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,Object> buildPipelineStageRunProgress;
        private @Nullable String timeFinished;
        private @Nullable String timeStarted;
        public Builder() {}
        public Builder(BuildRunBuildRunProgress defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.buildPipelineStageRunProgress = defaults.buildPipelineStageRunProgress;
    	      this.timeFinished = defaults.timeFinished;
    	      this.timeStarted = defaults.timeStarted;
        }

        @CustomType.Setter
        public Builder buildPipelineStageRunProgress(@Nullable Map<String,Object> buildPipelineStageRunProgress) {
            this.buildPipelineStageRunProgress = buildPipelineStageRunProgress;
            return this;
        }
        @CustomType.Setter
        public Builder timeFinished(@Nullable String timeFinished) {
            this.timeFinished = timeFinished;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(@Nullable String timeStarted) {
            this.timeStarted = timeStarted;
            return this;
        }
        public BuildRunBuildRunProgress build() {
            final var o = new BuildRunBuildRunProgress();
            o.buildPipelineStageRunProgress = buildPipelineStageRunProgress;
            o.timeFinished = timeFinished;
            o.timeStarted = timeStarted;
            return o;
        }
    }
}