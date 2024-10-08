// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DbSystemSource {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database system backup.
     * 
     */
    private @Nullable String backupId;
    /**
     * @return Deprecated. Don&#39;t use.
     * 
     */
    private @Nullable Boolean isHavingRestoreConfigOverrides;
    /**
     * @return The source descriminator. Example: `{&#34;source_type&#34;: &#34;BACKUP&#34;}`.
     * 
     */
    private String sourceType;

    private DbSystemSource() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database system backup.
     * 
     */
    public Optional<String> backupId() {
        return Optional.ofNullable(this.backupId);
    }
    /**
     * @return Deprecated. Don&#39;t use.
     * 
     */
    public Optional<Boolean> isHavingRestoreConfigOverrides() {
        return Optional.ofNullable(this.isHavingRestoreConfigOverrides);
    }
    /**
     * @return The source descriminator. Example: `{&#34;source_type&#34;: &#34;BACKUP&#34;}`.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DbSystemSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String backupId;
        private @Nullable Boolean isHavingRestoreConfigOverrides;
        private String sourceType;
        public Builder() {}
        public Builder(DbSystemSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupId = defaults.backupId;
    	      this.isHavingRestoreConfigOverrides = defaults.isHavingRestoreConfigOverrides;
    	      this.sourceType = defaults.sourceType;
        }

        @CustomType.Setter
        public Builder backupId(@Nullable String backupId) {

            this.backupId = backupId;
            return this;
        }
        @CustomType.Setter
        public Builder isHavingRestoreConfigOverrides(@Nullable Boolean isHavingRestoreConfigOverrides) {

            this.isHavingRestoreConfigOverrides = isHavingRestoreConfigOverrides;
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            if (sourceType == null) {
              throw new MissingRequiredPropertyException("DbSystemSource", "sourceType");
            }
            this.sourceType = sourceType;
            return this;
        }
        public DbSystemSource build() {
            final var _resultValue = new DbSystemSource();
            _resultValue.backupId = backupId;
            _resultValue.isHavingRestoreConfigOverrides = isHavingRestoreConfigOverrides;
            _resultValue.sourceType = sourceType;
            return _resultValue;
        }
    }
}
