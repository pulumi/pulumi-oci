// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBuildPipelineStagesBuildPipelineStageCollectionItemWaitCriteria {
    /**
     * @return The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
     * 
     */
    private String waitDuration;
    /**
     * @return Wait criteria type.
     * 
     */
    private String waitType;

    private GetBuildPipelineStagesBuildPipelineStageCollectionItemWaitCriteria() {}
    /**
     * @return The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
     * 
     */
    public String waitDuration() {
        return this.waitDuration;
    }
    /**
     * @return Wait criteria type.
     * 
     */
    public String waitType() {
        return this.waitType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildPipelineStagesBuildPipelineStageCollectionItemWaitCriteria defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String waitDuration;
        private String waitType;
        public Builder() {}
        public Builder(GetBuildPipelineStagesBuildPipelineStageCollectionItemWaitCriteria defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.waitDuration = defaults.waitDuration;
    	      this.waitType = defaults.waitType;
        }

        @CustomType.Setter
        public Builder waitDuration(String waitDuration) {
            this.waitDuration = Objects.requireNonNull(waitDuration);
            return this;
        }
        @CustomType.Setter
        public Builder waitType(String waitType) {
            this.waitType = Objects.requireNonNull(waitType);
            return this;
        }
        public GetBuildPipelineStagesBuildPipelineStageCollectionItemWaitCriteria build() {
            final var o = new GetBuildPipelineStagesBuildPipelineStageCollectionItemWaitCriteria();
            o.waitDuration = waitDuration;
            o.waitType = waitType;
            return o;
        }
    }
}