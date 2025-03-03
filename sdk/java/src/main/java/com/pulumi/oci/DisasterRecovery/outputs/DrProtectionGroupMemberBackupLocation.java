// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrProtectionGroupMemberBackupLocation {
    /**
     * @return (Updatable) The bucket name inside the object storage namespace.  Example: `operation_logs`
     * 
     */
    private @Nullable String bucket;
    /**
     * @return (Updatable) The namespace in the object storage bucket location (Note - this is usually the tenancy name).  Example: `myocitenancy`
     * 
     */
    private @Nullable String namespace;
    /**
     * @return The object name inside the object storage bucket.  Example: `switchover_plan_executions`
     * 
     */
    private @Nullable String object;

    private DrProtectionGroupMemberBackupLocation() {}
    /**
     * @return (Updatable) The bucket name inside the object storage namespace.  Example: `operation_logs`
     * 
     */
    public Optional<String> bucket() {
        return Optional.ofNullable(this.bucket);
    }
    /**
     * @return (Updatable) The namespace in the object storage bucket location (Note - this is usually the tenancy name).  Example: `myocitenancy`
     * 
     */
    public Optional<String> namespace() {
        return Optional.ofNullable(this.namespace);
    }
    /**
     * @return The object name inside the object storage bucket.  Example: `switchover_plan_executions`
     * 
     */
    public Optional<String> object() {
        return Optional.ofNullable(this.object);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrProtectionGroupMemberBackupLocation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String bucket;
        private @Nullable String namespace;
        private @Nullable String object;
        public Builder() {}
        public Builder(DrProtectionGroupMemberBackupLocation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
        }

        @CustomType.Setter
        public Builder bucket(@Nullable String bucket) {

            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(@Nullable String namespace) {

            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder object(@Nullable String object) {

            this.object = object;
            return this;
        }
        public DrProtectionGroupMemberBackupLocation build() {
            final var _resultValue = new DrProtectionGroupMemberBackupLocation();
            _resultValue.bucket = bucket;
            _resultValue.namespace = namespace;
            _resultValue.object = object;
            return _resultValue;
        }
    }
}
