// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Kms.outputs.GetKeyVersionExternalKeyReferenceDetail;
import com.pulumi.oci.Kms.outputs.GetKeyVersionReplicaDetail;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetKeyVersionResult {
    /**
     * @return The OCID of the compartment that contains this key version.
     * 
     */
    private String compartmentId;
    /**
     * @return Key reference data to be returned to the customer as a response.
     * 
     */
    private List<GetKeyVersionExternalKeyReferenceDetail> externalKeyReferenceDetails;
    /**
     * @return Key version ID associated with the external key.
     * 
     */
    private String externalKeyVersionId;
    /**
     * @return The OCID of the key version.
     * 
     */
    private String id;
    /**
     * @return An optional property indicating whether this keyversion is generated from auto rotatation.
     * 
     */
    private Boolean isAutoRotated;
    /**
     * @return A Boolean value that indicates whether the KeyVersion belongs to primary Vault or replica Vault.
     * 
     */
    private Boolean isPrimary;
    /**
     * @return The OCID of the master encryption key associated with this key version.
     * 
     */
    private String keyId;
    /**
     * @return The OCID of the key version.
     * 
     */
    private String keyVersionId;
    private String managementEndpoint;
    /**
     * @return The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
     * 
     */
    private String publicKey;
    /**
     * @return KeyVersion replica details
     * 
     */
    private List<GetKeyVersionReplicaDetail> replicaDetails;
    private String restoredFromKeyId;
    /**
     * @return The OCID of the key version from which this key version was restored.
     * 
     */
    private String restoredFromKeyVersionId;
    /**
     * @return The key version&#39;s current lifecycle state.  Example: `ENABLED`
     * 
     */
    private String state;
    /**
     * @return The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: &#34;2018-04-03T21:10:29.600Z&#34;
     * 
     */
    private String timeCreated;
    /**
     * @return An optional property to indicate when to delete the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    private String timeOfDeletion;
    /**
     * @return The OCID of the vault that contains this key version.
     * 
     */
    private String vaultId;

    private GetKeyVersionResult() {}
    /**
     * @return The OCID of the compartment that contains this key version.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Key reference data to be returned to the customer as a response.
     * 
     */
    public List<GetKeyVersionExternalKeyReferenceDetail> externalKeyReferenceDetails() {
        return this.externalKeyReferenceDetails;
    }
    /**
     * @return Key version ID associated with the external key.
     * 
     */
    public String externalKeyVersionId() {
        return this.externalKeyVersionId;
    }
    /**
     * @return The OCID of the key version.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return An optional property indicating whether this keyversion is generated from auto rotatation.
     * 
     */
    public Boolean isAutoRotated() {
        return this.isAutoRotated;
    }
    /**
     * @return A Boolean value that indicates whether the KeyVersion belongs to primary Vault or replica Vault.
     * 
     */
    public Boolean isPrimary() {
        return this.isPrimary;
    }
    /**
     * @return The OCID of the master encryption key associated with this key version.
     * 
     */
    public String keyId() {
        return this.keyId;
    }
    /**
     * @return The OCID of the key version.
     * 
     */
    public String keyVersionId() {
        return this.keyVersionId;
    }
    public String managementEndpoint() {
        return this.managementEndpoint;
    }
    /**
     * @return The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
     * 
     */
    public String publicKey() {
        return this.publicKey;
    }
    /**
     * @return KeyVersion replica details
     * 
     */
    public List<GetKeyVersionReplicaDetail> replicaDetails() {
        return this.replicaDetails;
    }
    public String restoredFromKeyId() {
        return this.restoredFromKeyId;
    }
    /**
     * @return The OCID of the key version from which this key version was restored.
     * 
     */
    public String restoredFromKeyVersionId() {
        return this.restoredFromKeyVersionId;
    }
    /**
     * @return The key version&#39;s current lifecycle state.  Example: `ENABLED`
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: &#34;2018-04-03T21:10:29.600Z&#34;
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return An optional property to indicate when to delete the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public String timeOfDeletion() {
        return this.timeOfDeletion;
    }
    /**
     * @return The OCID of the vault that contains this key version.
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetKeyVersionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetKeyVersionExternalKeyReferenceDetail> externalKeyReferenceDetails;
        private String externalKeyVersionId;
        private String id;
        private Boolean isAutoRotated;
        private Boolean isPrimary;
        private String keyId;
        private String keyVersionId;
        private String managementEndpoint;
        private String publicKey;
        private List<GetKeyVersionReplicaDetail> replicaDetails;
        private String restoredFromKeyId;
        private String restoredFromKeyVersionId;
        private String state;
        private String timeCreated;
        private String timeOfDeletion;
        private String vaultId;
        public Builder() {}
        public Builder(GetKeyVersionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.externalKeyReferenceDetails = defaults.externalKeyReferenceDetails;
    	      this.externalKeyVersionId = defaults.externalKeyVersionId;
    	      this.id = defaults.id;
    	      this.isAutoRotated = defaults.isAutoRotated;
    	      this.isPrimary = defaults.isPrimary;
    	      this.keyId = defaults.keyId;
    	      this.keyVersionId = defaults.keyVersionId;
    	      this.managementEndpoint = defaults.managementEndpoint;
    	      this.publicKey = defaults.publicKey;
    	      this.replicaDetails = defaults.replicaDetails;
    	      this.restoredFromKeyId = defaults.restoredFromKeyId;
    	      this.restoredFromKeyVersionId = defaults.restoredFromKeyVersionId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfDeletion = defaults.timeOfDeletion;
    	      this.vaultId = defaults.vaultId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder externalKeyReferenceDetails(List<GetKeyVersionExternalKeyReferenceDetail> externalKeyReferenceDetails) {
            if (externalKeyReferenceDetails == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "externalKeyReferenceDetails");
            }
            this.externalKeyReferenceDetails = externalKeyReferenceDetails;
            return this;
        }
        public Builder externalKeyReferenceDetails(GetKeyVersionExternalKeyReferenceDetail... externalKeyReferenceDetails) {
            return externalKeyReferenceDetails(List.of(externalKeyReferenceDetails));
        }
        @CustomType.Setter
        public Builder externalKeyVersionId(String externalKeyVersionId) {
            if (externalKeyVersionId == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "externalKeyVersionId");
            }
            this.externalKeyVersionId = externalKeyVersionId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isAutoRotated(Boolean isAutoRotated) {
            if (isAutoRotated == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "isAutoRotated");
            }
            this.isAutoRotated = isAutoRotated;
            return this;
        }
        @CustomType.Setter
        public Builder isPrimary(Boolean isPrimary) {
            if (isPrimary == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "isPrimary");
            }
            this.isPrimary = isPrimary;
            return this;
        }
        @CustomType.Setter
        public Builder keyId(String keyId) {
            if (keyId == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "keyId");
            }
            this.keyId = keyId;
            return this;
        }
        @CustomType.Setter
        public Builder keyVersionId(String keyVersionId) {
            if (keyVersionId == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "keyVersionId");
            }
            this.keyVersionId = keyVersionId;
            return this;
        }
        @CustomType.Setter
        public Builder managementEndpoint(String managementEndpoint) {
            if (managementEndpoint == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "managementEndpoint");
            }
            this.managementEndpoint = managementEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder publicKey(String publicKey) {
            if (publicKey == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "publicKey");
            }
            this.publicKey = publicKey;
            return this;
        }
        @CustomType.Setter
        public Builder replicaDetails(List<GetKeyVersionReplicaDetail> replicaDetails) {
            if (replicaDetails == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "replicaDetails");
            }
            this.replicaDetails = replicaDetails;
            return this;
        }
        public Builder replicaDetails(GetKeyVersionReplicaDetail... replicaDetails) {
            return replicaDetails(List.of(replicaDetails));
        }
        @CustomType.Setter
        public Builder restoredFromKeyId(String restoredFromKeyId) {
            if (restoredFromKeyId == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "restoredFromKeyId");
            }
            this.restoredFromKeyId = restoredFromKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder restoredFromKeyVersionId(String restoredFromKeyVersionId) {
            if (restoredFromKeyVersionId == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "restoredFromKeyVersionId");
            }
            this.restoredFromKeyVersionId = restoredFromKeyVersionId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeOfDeletion(String timeOfDeletion) {
            if (timeOfDeletion == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "timeOfDeletion");
            }
            this.timeOfDeletion = timeOfDeletion;
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(String vaultId) {
            if (vaultId == null) {
              throw new MissingRequiredPropertyException("GetKeyVersionResult", "vaultId");
            }
            this.vaultId = vaultId;
            return this;
        }
        public GetKeyVersionResult build() {
            final var _resultValue = new GetKeyVersionResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.externalKeyReferenceDetails = externalKeyReferenceDetails;
            _resultValue.externalKeyVersionId = externalKeyVersionId;
            _resultValue.id = id;
            _resultValue.isAutoRotated = isAutoRotated;
            _resultValue.isPrimary = isPrimary;
            _resultValue.keyId = keyId;
            _resultValue.keyVersionId = keyVersionId;
            _resultValue.managementEndpoint = managementEndpoint;
            _resultValue.publicKey = publicKey;
            _resultValue.replicaDetails = replicaDetails;
            _resultValue.restoredFromKeyId = restoredFromKeyId;
            _resultValue.restoredFromKeyVersionId = restoredFromKeyVersionId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeOfDeletion = timeOfDeletion;
            _resultValue.vaultId = vaultId;
            return _resultValue;
        }
    }
}
