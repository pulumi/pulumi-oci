// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class UserAssessmentIgnoredTarget {
    private @Nullable String lifecycleState;
    /**
     * @return The OCID of the target database on which the user assessment is to be run.
     * 
     */
    private @Nullable String targetId;
    private @Nullable String userAssessmentId;

    private UserAssessmentIgnoredTarget() {}
    public Optional<String> lifecycleState() {
        return Optional.ofNullable(this.lifecycleState);
    }
    /**
     * @return The OCID of the target database on which the user assessment is to be run.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }
    public Optional<String> userAssessmentId() {
        return Optional.ofNullable(this.userAssessmentId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(UserAssessmentIgnoredTarget defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String lifecycleState;
        private @Nullable String targetId;
        private @Nullable String userAssessmentId;
        public Builder() {}
        public Builder(UserAssessmentIgnoredTarget defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.lifecycleState = defaults.lifecycleState;
    	      this.targetId = defaults.targetId;
    	      this.userAssessmentId = defaults.userAssessmentId;
        }

        @CustomType.Setter
        public Builder lifecycleState(@Nullable String lifecycleState) {
            this.lifecycleState = lifecycleState;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(@Nullable String targetId) {
            this.targetId = targetId;
            return this;
        }
        @CustomType.Setter
        public Builder userAssessmentId(@Nullable String userAssessmentId) {
            this.userAssessmentId = userAssessmentId;
            return this;
        }
        public UserAssessmentIgnoredTarget build() {
            final var o = new UserAssessmentIgnoredTarget();
            o.lifecycleState = lifecycleState;
            o.targetId = targetId;
            o.userAssessmentId = userAssessmentId;
            return o;
        }
    }
}