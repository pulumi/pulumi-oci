// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Mysql.outputs.MysqlDbSystemBackupPolicyPitrPolicy;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MysqlDbSystemBackupPolicy {
    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,Object> definedTags;
    /**
     * @return (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,Object> freeformTags;
    /**
     * @return (Updatable) Specifies if PITR is enabled or disabled.
     * 
     */
    private @Nullable Boolean isEnabled;
    /**
     * @return (Updatable) The PITR policy for the DB System.
     * 
     */
    private @Nullable MysqlDbSystemBackupPolicyPitrPolicy pitrPolicy;
    /**
     * @return (Updatable) Number of days to retain an automatic backup.
     * 
     */
    private @Nullable Integer retentionInDays;
    /**
     * @return (Updatable) The start of the 2 hour maintenance window.
     * 
     */
    private @Nullable String windowStartTime;

    private MysqlDbSystemBackupPolicy() {}
    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return (Updatable) Specifies if PITR is enabled or disabled.
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }
    /**
     * @return (Updatable) The PITR policy for the DB System.
     * 
     */
    public Optional<MysqlDbSystemBackupPolicyPitrPolicy> pitrPolicy() {
        return Optional.ofNullable(this.pitrPolicy);
    }
    /**
     * @return (Updatable) Number of days to retain an automatic backup.
     * 
     */
    public Optional<Integer> retentionInDays() {
        return Optional.ofNullable(this.retentionInDays);
    }
    /**
     * @return (Updatable) The start of the 2 hour maintenance window.
     * 
     */
    public Optional<String> windowStartTime() {
        return Optional.ofNullable(this.windowStartTime);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlDbSystemBackupPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,Object> definedTags;
        private @Nullable Map<String,Object> freeformTags;
        private @Nullable Boolean isEnabled;
        private @Nullable MysqlDbSystemBackupPolicyPitrPolicy pitrPolicy;
        private @Nullable Integer retentionInDays;
        private @Nullable String windowStartTime;
        public Builder() {}
        public Builder(MysqlDbSystemBackupPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.isEnabled = defaults.isEnabled;
    	      this.pitrPolicy = defaults.pitrPolicy;
    	      this.retentionInDays = defaults.retentionInDays;
    	      this.windowStartTime = defaults.windowStartTime;
        }

        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,Object> definedTags) {
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,Object> freeformTags) {
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder pitrPolicy(@Nullable MysqlDbSystemBackupPolicyPitrPolicy pitrPolicy) {
            this.pitrPolicy = pitrPolicy;
            return this;
        }
        @CustomType.Setter
        public Builder retentionInDays(@Nullable Integer retentionInDays) {
            this.retentionInDays = retentionInDays;
            return this;
        }
        @CustomType.Setter
        public Builder windowStartTime(@Nullable String windowStartTime) {
            this.windowStartTime = windowStartTime;
            return this;
        }
        public MysqlDbSystemBackupPolicy build() {
            final var o = new MysqlDbSystemBackupPolicy();
            o.definedTags = definedTags;
            o.freeformTags = freeformTags;
            o.isEnabled = isEnabled;
            o.pitrPolicy = pitrPolicy;
            o.retentionInDays = retentionInDays;
            o.windowStartTime = windowStartTime;
            return o;
        }
    }
}