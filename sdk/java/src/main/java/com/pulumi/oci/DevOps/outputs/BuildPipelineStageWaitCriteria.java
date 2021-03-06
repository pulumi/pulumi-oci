// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class BuildPipelineStageWaitCriteria {
    /**
     * @return (Updatable) The absolute wait duration. Minimum wait duration must be 5 seconds. Maximum wait duration can be up to 2 days.
     * 
     */
    private final String waitDuration;
    /**
     * @return (Updatable) Wait criteria type.
     * 
     */
    private final String waitType;

    @CustomType.Constructor
    private BuildPipelineStageWaitCriteria(
        @CustomType.Parameter("waitDuration") String waitDuration,
        @CustomType.Parameter("waitType") String waitType) {
        this.waitDuration = waitDuration;
        this.waitType = waitType;
    }

    /**
     * @return (Updatable) The absolute wait duration. Minimum wait duration must be 5 seconds. Maximum wait duration can be up to 2 days.
     * 
     */
    public String waitDuration() {
        return this.waitDuration;
    }
    /**
     * @return (Updatable) Wait criteria type.
     * 
     */
    public String waitType() {
        return this.waitType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BuildPipelineStageWaitCriteria defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String waitDuration;
        private String waitType;

        public Builder() {
    	      // Empty
        }

        public Builder(BuildPipelineStageWaitCriteria defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.waitDuration = defaults.waitDuration;
    	      this.waitType = defaults.waitType;
        }

        public Builder waitDuration(String waitDuration) {
            this.waitDuration = Objects.requireNonNull(waitDuration);
            return this;
        }
        public Builder waitType(String waitType) {
            this.waitType = Objects.requireNonNull(waitType);
            return this;
        }        public BuildPipelineStageWaitCriteria build() {
            return new BuildPipelineStageWaitCriteria(waitDuration, waitType);
        }
    }
}
