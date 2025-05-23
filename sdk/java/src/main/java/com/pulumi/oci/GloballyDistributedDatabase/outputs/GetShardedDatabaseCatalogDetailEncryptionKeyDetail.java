// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GloballyDistributedDatabase.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetShardedDatabaseCatalogDetailEncryptionKeyDetail {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key in vault identified by vaultId in customer tenancy  that is used as the master encryption key.
     * 
     */
    private String kmsKeyId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key version for key identified by kmsKeyId that is used in data encryption (TDE) operations.
     * 
     */
    private String kmsKeyVersionId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the vault in customer tenancy where KMS key is present. For shard or catalog with cross-region data guard enabled, user needs to make sure to provide virtual private vault only, which is also replicated in the region of standby shard.
     * 
     */
    private String vaultId;

    private GetShardedDatabaseCatalogDetailEncryptionKeyDetail() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key in vault identified by vaultId in customer tenancy  that is used as the master encryption key.
     * 
     */
    public String kmsKeyId() {
        return this.kmsKeyId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key version for key identified by kmsKeyId that is used in data encryption (TDE) operations.
     * 
     */
    public String kmsKeyVersionId() {
        return this.kmsKeyVersionId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the vault in customer tenancy where KMS key is present. For shard or catalog with cross-region data guard enabled, user needs to make sure to provide virtual private vault only, which is also replicated in the region of standby shard.
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShardedDatabaseCatalogDetailEncryptionKeyDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String kmsKeyId;
        private String kmsKeyVersionId;
        private String vaultId;
        public Builder() {}
        public Builder(GetShardedDatabaseCatalogDetailEncryptionKeyDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.kmsKeyVersionId = defaults.kmsKeyVersionId;
    	      this.vaultId = defaults.vaultId;
        }

        @CustomType.Setter
        public Builder kmsKeyId(String kmsKeyId) {
            if (kmsKeyId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseCatalogDetailEncryptionKeyDetail", "kmsKeyId");
            }
            this.kmsKeyId = kmsKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyVersionId(String kmsKeyVersionId) {
            if (kmsKeyVersionId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseCatalogDetailEncryptionKeyDetail", "kmsKeyVersionId");
            }
            this.kmsKeyVersionId = kmsKeyVersionId;
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(String vaultId) {
            if (vaultId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseCatalogDetailEncryptionKeyDetail", "vaultId");
            }
            this.vaultId = vaultId;
            return this;
        }
        public GetShardedDatabaseCatalogDetailEncryptionKeyDetail build() {
            final var _resultValue = new GetShardedDatabaseCatalogDetailEncryptionKeyDetail();
            _resultValue.kmsKeyId = kmsKeyId;
            _resultValue.kmsKeyVersionId = kmsKeyVersionId;
            _resultValue.vaultId = vaultId;
            return _resultValue;
        }
    }
}
