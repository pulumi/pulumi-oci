// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Kms.outputs.GetVaultsVaultReplicaDetail;
import com.pulumi.oci.Kms.outputs.GetVaultsVaultRestoreFromFile;
import com.pulumi.oci.Kms.outputs.GetVaultsVaultRestoreFromObjectStore;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetVaultsVault {
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The service endpoint to perform cryptographic operations against. Cryptographic operations include [Encrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/EncryptedData/Encrypt), [Decrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/DecryptedData/Decrypt), and [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) operations.
     * 
     */
    private String cryptoEndpoint;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A user-friendly name for the vault. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of the vault.
     * 
     */
    private String id;
    /**
     * @return A boolean that will be true when vault is primary, and will be false when vault is a replica from a primary vault.
     * 
     */
    private Boolean isPrimary;
    /**
     * @return The service endpoint to perform management operations against. Management operations include &#34;Create,&#34; &#34;Update,&#34; &#34;List,&#34; &#34;Get,&#34; and &#34;Delete&#34; operations.
     * 
     */
    private String managementEndpoint;
    /**
     * @return Vault replica details
     * 
     */
    private List<GetVaultsVaultReplicaDetail> replicaDetails;
    private List<GetVaultsVaultRestoreFromFile> restoreFromFiles;
    private List<GetVaultsVaultRestoreFromObjectStore> restoreFromObjectStores;
    private Boolean restoreTrigger;
    /**
     * @return The OCID of the vault from which this vault was restored, if it was restored from a backup file.  If you restore a vault to the same region, the vault retains the same OCID that it had when you  backed up the vault.
     * 
     */
    private String restoredFromVaultId;
    /**
     * @return The vault&#39;s current lifecycle state.  Example: `DELETED`
     * 
     */
    private String state;
    /**
     * @return The date and time this vault was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return An optional property to indicate when to delete the vault, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeOfDeletion;
    /**
     * @return The type of vault. Each type of vault stores the key with different degrees of isolation and has different options and pricing.
     * 
     */
    private String vaultType;

    private GetVaultsVault() {}
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The service endpoint to perform cryptographic operations against. Cryptographic operations include [Encrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/EncryptedData/Encrypt), [Decrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/DecryptedData/Decrypt), and [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) operations.
     * 
     */
    public String cryptoEndpoint() {
        return this.cryptoEndpoint;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name for the vault. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the vault.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A boolean that will be true when vault is primary, and will be false when vault is a replica from a primary vault.
     * 
     */
    public Boolean isPrimary() {
        return this.isPrimary;
    }
    /**
     * @return The service endpoint to perform management operations against. Management operations include &#34;Create,&#34; &#34;Update,&#34; &#34;List,&#34; &#34;Get,&#34; and &#34;Delete&#34; operations.
     * 
     */
    public String managementEndpoint() {
        return this.managementEndpoint;
    }
    /**
     * @return Vault replica details
     * 
     */
    public List<GetVaultsVaultReplicaDetail> replicaDetails() {
        return this.replicaDetails;
    }
    public List<GetVaultsVaultRestoreFromFile> restoreFromFiles() {
        return this.restoreFromFiles;
    }
    public List<GetVaultsVaultRestoreFromObjectStore> restoreFromObjectStores() {
        return this.restoreFromObjectStores;
    }
    public Boolean restoreTrigger() {
        return this.restoreTrigger;
    }
    /**
     * @return The OCID of the vault from which this vault was restored, if it was restored from a backup file.  If you restore a vault to the same region, the vault retains the same OCID that it had when you  backed up the vault.
     * 
     */
    public String restoredFromVaultId() {
        return this.restoredFromVaultId;
    }
    /**
     * @return The vault&#39;s current lifecycle state.  Example: `DELETED`
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time this vault was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return An optional property to indicate when to delete the vault, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeOfDeletion() {
        return this.timeOfDeletion;
    }
    /**
     * @return The type of vault. Each type of vault stores the key with different degrees of isolation and has different options and pricing.
     * 
     */
    public String vaultType() {
        return this.vaultType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVaultsVault defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String cryptoEndpoint;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isPrimary;
        private String managementEndpoint;
        private List<GetVaultsVaultReplicaDetail> replicaDetails;
        private List<GetVaultsVaultRestoreFromFile> restoreFromFiles;
        private List<GetVaultsVaultRestoreFromObjectStore> restoreFromObjectStores;
        private Boolean restoreTrigger;
        private String restoredFromVaultId;
        private String state;
        private String timeCreated;
        private String timeOfDeletion;
        private String vaultType;
        public Builder() {}
        public Builder(GetVaultsVault defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.cryptoEndpoint = defaults.cryptoEndpoint;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isPrimary = defaults.isPrimary;
    	      this.managementEndpoint = defaults.managementEndpoint;
    	      this.replicaDetails = defaults.replicaDetails;
    	      this.restoreFromFiles = defaults.restoreFromFiles;
    	      this.restoreFromObjectStores = defaults.restoreFromObjectStores;
    	      this.restoreTrigger = defaults.restoreTrigger;
    	      this.restoredFromVaultId = defaults.restoredFromVaultId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfDeletion = defaults.timeOfDeletion;
    	      this.vaultType = defaults.vaultType;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder cryptoEndpoint(String cryptoEndpoint) {
            this.cryptoEndpoint = Objects.requireNonNull(cryptoEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isPrimary(Boolean isPrimary) {
            this.isPrimary = Objects.requireNonNull(isPrimary);
            return this;
        }
        @CustomType.Setter
        public Builder managementEndpoint(String managementEndpoint) {
            this.managementEndpoint = Objects.requireNonNull(managementEndpoint);
            return this;
        }
        @CustomType.Setter
        public Builder replicaDetails(List<GetVaultsVaultReplicaDetail> replicaDetails) {
            this.replicaDetails = Objects.requireNonNull(replicaDetails);
            return this;
        }
        public Builder replicaDetails(GetVaultsVaultReplicaDetail... replicaDetails) {
            return replicaDetails(List.of(replicaDetails));
        }
        @CustomType.Setter
        public Builder restoreFromFiles(List<GetVaultsVaultRestoreFromFile> restoreFromFiles) {
            this.restoreFromFiles = Objects.requireNonNull(restoreFromFiles);
            return this;
        }
        public Builder restoreFromFiles(GetVaultsVaultRestoreFromFile... restoreFromFiles) {
            return restoreFromFiles(List.of(restoreFromFiles));
        }
        @CustomType.Setter
        public Builder restoreFromObjectStores(List<GetVaultsVaultRestoreFromObjectStore> restoreFromObjectStores) {
            this.restoreFromObjectStores = Objects.requireNonNull(restoreFromObjectStores);
            return this;
        }
        public Builder restoreFromObjectStores(GetVaultsVaultRestoreFromObjectStore... restoreFromObjectStores) {
            return restoreFromObjectStores(List.of(restoreFromObjectStores));
        }
        @CustomType.Setter
        public Builder restoreTrigger(Boolean restoreTrigger) {
            this.restoreTrigger = Objects.requireNonNull(restoreTrigger);
            return this;
        }
        @CustomType.Setter
        public Builder restoredFromVaultId(String restoredFromVaultId) {
            this.restoredFromVaultId = Objects.requireNonNull(restoredFromVaultId);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeOfDeletion(String timeOfDeletion) {
            this.timeOfDeletion = Objects.requireNonNull(timeOfDeletion);
            return this;
        }
        @CustomType.Setter
        public Builder vaultType(String vaultType) {
            this.vaultType = Objects.requireNonNull(vaultType);
            return this;
        }
        public GetVaultsVault build() {
            final var o = new GetVaultsVault();
            o.compartmentId = compartmentId;
            o.cryptoEndpoint = cryptoEndpoint;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isPrimary = isPrimary;
            o.managementEndpoint = managementEndpoint;
            o.replicaDetails = replicaDetails;
            o.restoreFromFiles = restoreFromFiles;
            o.restoreFromObjectStores = restoreFromObjectStores;
            o.restoreTrigger = restoreTrigger;
            o.restoredFromVaultId = restoredFromVaultId;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeOfDeletion = timeOfDeletion;
            o.vaultType = vaultType;
            return o;
        }
    }
}