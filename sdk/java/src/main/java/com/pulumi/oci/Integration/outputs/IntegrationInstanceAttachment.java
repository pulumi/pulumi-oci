// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Integration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class IntegrationInstanceAttachment {
    /**
     * @return * If role == `PARENT`, the attached instance was created by this service instance
     * * If role == `CHILD`, this instance was created from attached instance on behalf of a user
     * 
     */
    private @Nullable Boolean isImplicit;
    /**
     * @return The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
     * 
     */
    private @Nullable String targetId;
    /**
     * @return The dataplane instance URL of the attached instance
     * 
     */
    private @Nullable String targetInstanceUrl;
    /**
     * @return The role of the target attachment.
     * * `PARENT` - The target instance is the parent of this attachment.
     * * `CHILD` - The target instance is the child of this attachment.
     * 
     */
    private @Nullable String targetRole;
    /**
     * @return The type of the target instance, such as &#34;FUSION&#34;.
     * 
     */
    private @Nullable String targetServiceType;

    private IntegrationInstanceAttachment() {}
    /**
     * @return * If role == `PARENT`, the attached instance was created by this service instance
     * * If role == `CHILD`, this instance was created from attached instance on behalf of a user
     * 
     */
    public Optional<Boolean> isImplicit() {
        return Optional.ofNullable(this.isImplicit);
    }
    /**
     * @return The OCID of the target instance (which could be any other Oracle Cloud Infrastructure PaaS/SaaS resource), to which this instance is attached.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }
    /**
     * @return The dataplane instance URL of the attached instance
     * 
     */
    public Optional<String> targetInstanceUrl() {
        return Optional.ofNullable(this.targetInstanceUrl);
    }
    /**
     * @return The role of the target attachment.
     * * `PARENT` - The target instance is the parent of this attachment.
     * * `CHILD` - The target instance is the child of this attachment.
     * 
     */
    public Optional<String> targetRole() {
        return Optional.ofNullable(this.targetRole);
    }
    /**
     * @return The type of the target instance, such as &#34;FUSION&#34;.
     * 
     */
    public Optional<String> targetServiceType() {
        return Optional.ofNullable(this.targetServiceType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(IntegrationInstanceAttachment defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isImplicit;
        private @Nullable String targetId;
        private @Nullable String targetInstanceUrl;
        private @Nullable String targetRole;
        private @Nullable String targetServiceType;
        public Builder() {}
        public Builder(IntegrationInstanceAttachment defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isImplicit = defaults.isImplicit;
    	      this.targetId = defaults.targetId;
    	      this.targetInstanceUrl = defaults.targetInstanceUrl;
    	      this.targetRole = defaults.targetRole;
    	      this.targetServiceType = defaults.targetServiceType;
        }

        @CustomType.Setter
        public Builder isImplicit(@Nullable Boolean isImplicit) {

            this.isImplicit = isImplicit;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(@Nullable String targetId) {

            this.targetId = targetId;
            return this;
        }
        @CustomType.Setter
        public Builder targetInstanceUrl(@Nullable String targetInstanceUrl) {

            this.targetInstanceUrl = targetInstanceUrl;
            return this;
        }
        @CustomType.Setter
        public Builder targetRole(@Nullable String targetRole) {

            this.targetRole = targetRole;
            return this;
        }
        @CustomType.Setter
        public Builder targetServiceType(@Nullable String targetServiceType) {

            this.targetServiceType = targetServiceType;
            return this;
        }
        public IntegrationInstanceAttachment build() {
            final var _resultValue = new IntegrationInstanceAttachment();
            _resultValue.isImplicit = isImplicit;
            _resultValue.targetId = targetId;
            _resultValue.targetInstanceUrl = targetInstanceUrl;
            _resultValue.targetRole = targetRole;
            _resultValue.targetServiceType = targetServiceType;
            return _resultValue;
        }
    }
}
