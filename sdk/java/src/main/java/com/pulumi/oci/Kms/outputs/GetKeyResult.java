// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Kms.outputs.GetKeyKeyShape;
import com.pulumi.oci.Kms.outputs.GetKeyReplicaDetail;
import com.pulumi.oci.Kms.outputs.GetKeyRestoreFromFile;
import com.pulumi.oci.Kms.outputs.GetKeyRestoreFromObjectStore;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetKeyResult {
    /**
     * @return The OCID of the compartment that contains this master encryption key.
     * 
     */
    private final String compartmentId;
    /**
     * @return The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
     * 
     */
    private final String currentKeyVersion;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    private final String desiredState;
    /**
     * @return A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID of the key.
     * 
     */
    private final String id;
    /**
     * @return A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
     * 
     */
    private final Boolean isPrimary;
    private final String keyId;
    /**
     * @return The cryptographic properties of a key.
     * 
     */
    private final List<GetKeyKeyShape> keyShapes;
    private final String managementEndpoint;
    /**
     * @return The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
     * 
     */
    private final String protectionMode;
    /**
     * @return Key replica details
     * 
     */
    private final List<GetKeyReplicaDetail> replicaDetails;
    /**
     * @return Details where key was backed up.
     * 
     */
    private final List<GetKeyRestoreFromFile> restoreFromFiles;
    /**
     * @return Details where key was backed up
     * 
     */
    private final List<GetKeyRestoreFromObjectStore> restoreFromObjectStores;
    /**
     * @return When flipped, triggers restore if restore options are provided. Values of 0 or 1 are supported.
     * 
     */
    private final Boolean restoreTrigger;
    /**
     * @return The OCID of the key from which this key was restored.
     * 
     */
    private final String restoredFromKeyId;
    /**
     * @return The key&#39;s current lifecycle state.  Example: `ENABLED`
     * 
     */
    private final String state;
    /**
     * @return The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return An optional property indicating when to delete the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    private final String timeOfDeletion;
    /**
     * @return The OCID of the vault that contains this key.
     * 
     */
    private final String vaultId;

    @CustomType.Constructor
    private GetKeyResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("currentKeyVersion") String currentKeyVersion,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("desiredState") String desiredState,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isPrimary") Boolean isPrimary,
        @CustomType.Parameter("keyId") String keyId,
        @CustomType.Parameter("keyShapes") List<GetKeyKeyShape> keyShapes,
        @CustomType.Parameter("managementEndpoint") String managementEndpoint,
        @CustomType.Parameter("protectionMode") String protectionMode,
        @CustomType.Parameter("replicaDetails") List<GetKeyReplicaDetail> replicaDetails,
        @CustomType.Parameter("restoreFromFiles") List<GetKeyRestoreFromFile> restoreFromFiles,
        @CustomType.Parameter("restoreFromObjectStores") List<GetKeyRestoreFromObjectStore> restoreFromObjectStores,
        @CustomType.Parameter("restoreTrigger") Boolean restoreTrigger,
        @CustomType.Parameter("restoredFromKeyId") String restoredFromKeyId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeOfDeletion") String timeOfDeletion,
        @CustomType.Parameter("vaultId") String vaultId) {
        this.compartmentId = compartmentId;
        this.currentKeyVersion = currentKeyVersion;
        this.definedTags = definedTags;
        this.desiredState = desiredState;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isPrimary = isPrimary;
        this.keyId = keyId;
        this.keyShapes = keyShapes;
        this.managementEndpoint = managementEndpoint;
        this.protectionMode = protectionMode;
        this.replicaDetails = replicaDetails;
        this.restoreFromFiles = restoreFromFiles;
        this.restoreFromObjectStores = restoreFromObjectStores;
        this.restoreTrigger = restoreTrigger;
        this.restoredFromKeyId = restoredFromKeyId;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeOfDeletion = timeOfDeletion;
        this.vaultId = vaultId;
    }

    /**
     * @return The OCID of the compartment that contains this master encryption key.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The OCID of the key version used in cryptographic operations. During key rotation, the service might be in a transitional state where this or a newer key version are used intermittently. The `currentKeyVersion` property is updated when the service is guaranteed to use the new key version for all subsequent encryption operations.
     * 
     */
    public String currentKeyVersion() {
        return this.currentKeyVersion;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    public String desiredState() {
        return this.desiredState;
    }
    /**
     * @return A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
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
     * @return The OCID of the key.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A boolean that will be true when key is primary, and will be false when key is a replica from a primary key.
     * 
     */
    public Boolean isPrimary() {
        return this.isPrimary;
    }
    public String keyId() {
        return this.keyId;
    }
    /**
     * @return The cryptographic properties of a key.
     * 
     */
    public List<GetKeyKeyShape> keyShapes() {
        return this.keyShapes;
    }
    public String managementEndpoint() {
        return this.managementEndpoint;
    }
    /**
     * @return The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
     * 
     */
    public String protectionMode() {
        return this.protectionMode;
    }
    /**
     * @return Key replica details
     * 
     */
    public List<GetKeyReplicaDetail> replicaDetails() {
        return this.replicaDetails;
    }
    /**
     * @return Details where key was backed up.
     * 
     */
    public List<GetKeyRestoreFromFile> restoreFromFiles() {
        return this.restoreFromFiles;
    }
    /**
     * @return Details where key was backed up
     * 
     */
    public List<GetKeyRestoreFromObjectStore> restoreFromObjectStores() {
        return this.restoreFromObjectStores;
    }
    /**
     * @return When flipped, triggers restore if restore options are provided. Values of 0 or 1 are supported.
     * 
     */
    public Boolean restoreTrigger() {
        return this.restoreTrigger;
    }
    /**
     * @return The OCID of the key from which this key was restored.
     * 
     */
    public String restoredFromKeyId() {
        return this.restoredFromKeyId;
    }
    /**
     * @return The key&#39;s current lifecycle state.  Example: `ENABLED`
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the key was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return An optional property indicating when to delete the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public String timeOfDeletion() {
        return this.timeOfDeletion;
    }
    /**
     * @return The OCID of the vault that contains this key.
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetKeyResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String currentKeyVersion;
        private Map<String,Object> definedTags;
        private String desiredState;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isPrimary;
        private String keyId;
        private List<GetKeyKeyShape> keyShapes;
        private String managementEndpoint;
        private String protectionMode;
        private List<GetKeyReplicaDetail> replicaDetails;
        private List<GetKeyRestoreFromFile> restoreFromFiles;
        private List<GetKeyRestoreFromObjectStore> restoreFromObjectStores;
        private Boolean restoreTrigger;
        private String restoredFromKeyId;
        private String state;
        private String timeCreated;
        private String timeOfDeletion;
        private String vaultId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetKeyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.currentKeyVersion = defaults.currentKeyVersion;
    	      this.definedTags = defaults.definedTags;
    	      this.desiredState = defaults.desiredState;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isPrimary = defaults.isPrimary;
    	      this.keyId = defaults.keyId;
    	      this.keyShapes = defaults.keyShapes;
    	      this.managementEndpoint = defaults.managementEndpoint;
    	      this.protectionMode = defaults.protectionMode;
    	      this.replicaDetails = defaults.replicaDetails;
    	      this.restoreFromFiles = defaults.restoreFromFiles;
    	      this.restoreFromObjectStores = defaults.restoreFromObjectStores;
    	      this.restoreTrigger = defaults.restoreTrigger;
    	      this.restoredFromKeyId = defaults.restoredFromKeyId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfDeletion = defaults.timeOfDeletion;
    	      this.vaultId = defaults.vaultId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder currentKeyVersion(String currentKeyVersion) {
            this.currentKeyVersion = Objects.requireNonNull(currentKeyVersion);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder desiredState(String desiredState) {
            this.desiredState = Objects.requireNonNull(desiredState);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isPrimary(Boolean isPrimary) {
            this.isPrimary = Objects.requireNonNull(isPrimary);
            return this;
        }
        public Builder keyId(String keyId) {
            this.keyId = Objects.requireNonNull(keyId);
            return this;
        }
        public Builder keyShapes(List<GetKeyKeyShape> keyShapes) {
            this.keyShapes = Objects.requireNonNull(keyShapes);
            return this;
        }
        public Builder keyShapes(GetKeyKeyShape... keyShapes) {
            return keyShapes(List.of(keyShapes));
        }
        public Builder managementEndpoint(String managementEndpoint) {
            this.managementEndpoint = Objects.requireNonNull(managementEndpoint);
            return this;
        }
        public Builder protectionMode(String protectionMode) {
            this.protectionMode = Objects.requireNonNull(protectionMode);
            return this;
        }
        public Builder replicaDetails(List<GetKeyReplicaDetail> replicaDetails) {
            this.replicaDetails = Objects.requireNonNull(replicaDetails);
            return this;
        }
        public Builder replicaDetails(GetKeyReplicaDetail... replicaDetails) {
            return replicaDetails(List.of(replicaDetails));
        }
        public Builder restoreFromFiles(List<GetKeyRestoreFromFile> restoreFromFiles) {
            this.restoreFromFiles = Objects.requireNonNull(restoreFromFiles);
            return this;
        }
        public Builder restoreFromFiles(GetKeyRestoreFromFile... restoreFromFiles) {
            return restoreFromFiles(List.of(restoreFromFiles));
        }
        public Builder restoreFromObjectStores(List<GetKeyRestoreFromObjectStore> restoreFromObjectStores) {
            this.restoreFromObjectStores = Objects.requireNonNull(restoreFromObjectStores);
            return this;
        }
        public Builder restoreFromObjectStores(GetKeyRestoreFromObjectStore... restoreFromObjectStores) {
            return restoreFromObjectStores(List.of(restoreFromObjectStores));
        }
        public Builder restoreTrigger(Boolean restoreTrigger) {
            this.restoreTrigger = Objects.requireNonNull(restoreTrigger);
            return this;
        }
        public Builder restoredFromKeyId(String restoredFromKeyId) {
            this.restoredFromKeyId = Objects.requireNonNull(restoredFromKeyId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeOfDeletion(String timeOfDeletion) {
            this.timeOfDeletion = Objects.requireNonNull(timeOfDeletion);
            return this;
        }
        public Builder vaultId(String vaultId) {
            this.vaultId = Objects.requireNonNull(vaultId);
            return this;
        }        public GetKeyResult build() {
            return new GetKeyResult(compartmentId, currentKeyVersion, definedTags, desiredState, displayName, freeformTags, id, isPrimary, keyId, keyShapes, managementEndpoint, protectionMode, replicaDetails, restoreFromFiles, restoreFromObjectStores, restoreTrigger, restoredFromKeyId, state, timeCreated, timeOfDeletion, vaultId);
        }
    }
}
