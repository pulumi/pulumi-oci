// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey {
    /**
     * @return AWS ARN role
     * 
     */
    private String arnRole;
    /**
     * @return The provider for the Autonomous Database encryption key.
     * 
     */
    private String autonomousDatabasesCloneProvider;
    /**
     * @return OKV certificate directory name
     * 
     */
    private String certificateDirectoryName;
    /**
     * @return OKV certificate id
     * 
     */
    private String certificateId;
    /**
     * @return OKV wallet directory name
     * 
     */
    private String directoryName;
    /**
     * @return AWS external ID
     * 
     */
    private String externalId;
    /**
     * @return AWS key ARN
     * 
     */
    private String keyArn;
    /**
     * @return Azure key name
     * 
     */
    private String keyName;
    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    private String kmsKeyId;
    /**
     * @return UUID of OKV KMS Key
     * 
     */
    private String okvKmsKey;
    /**
     * @return URI of OKV server
     * 
     */
    private String okvUri;
    /**
     * @return AWS key service endpoint URI
     * 
     */
    private String serviceEndpointUri;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    private String vaultId;
    /**
     * @return Azure vault URI
     * 
     */
    private String vaultUri;

    private GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey() {}
    /**
     * @return AWS ARN role
     * 
     */
    public String arnRole() {
        return this.arnRole;
    }
    /**
     * @return The provider for the Autonomous Database encryption key.
     * 
     */
    public String autonomousDatabasesCloneProvider() {
        return this.autonomousDatabasesCloneProvider;
    }
    /**
     * @return OKV certificate directory name
     * 
     */
    public String certificateDirectoryName() {
        return this.certificateDirectoryName;
    }
    /**
     * @return OKV certificate id
     * 
     */
    public String certificateId() {
        return this.certificateId;
    }
    /**
     * @return OKV wallet directory name
     * 
     */
    public String directoryName() {
        return this.directoryName;
    }
    /**
     * @return AWS external ID
     * 
     */
    public String externalId() {
        return this.externalId;
    }
    /**
     * @return AWS key ARN
     * 
     */
    public String keyArn() {
        return this.keyArn;
    }
    /**
     * @return Azure key name
     * 
     */
    public String keyName() {
        return this.keyName;
    }
    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    public String kmsKeyId() {
        return this.kmsKeyId;
    }
    /**
     * @return UUID of OKV KMS Key
     * 
     */
    public String okvKmsKey() {
        return this.okvKmsKey;
    }
    /**
     * @return URI of OKV server
     * 
     */
    public String okvUri() {
        return this.okvUri;
    }
    /**
     * @return AWS key service endpoint URI
     * 
     */
    public String serviceEndpointUri() {
        return this.serviceEndpointUri;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }
    /**
     * @return Azure vault URI
     * 
     */
    public String vaultUri() {
        return this.vaultUri;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String arnRole;
        private String autonomousDatabasesCloneProvider;
        private String certificateDirectoryName;
        private String certificateId;
        private String directoryName;
        private String externalId;
        private String keyArn;
        private String keyName;
        private String kmsKeyId;
        private String okvKmsKey;
        private String okvUri;
        private String serviceEndpointUri;
        private String vaultId;
        private String vaultUri;
        public Builder() {}
        public Builder(GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.arnRole = defaults.arnRole;
    	      this.autonomousDatabasesCloneProvider = defaults.autonomousDatabasesCloneProvider;
    	      this.certificateDirectoryName = defaults.certificateDirectoryName;
    	      this.certificateId = defaults.certificateId;
    	      this.directoryName = defaults.directoryName;
    	      this.externalId = defaults.externalId;
    	      this.keyArn = defaults.keyArn;
    	      this.keyName = defaults.keyName;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.okvKmsKey = defaults.okvKmsKey;
    	      this.okvUri = defaults.okvUri;
    	      this.serviceEndpointUri = defaults.serviceEndpointUri;
    	      this.vaultId = defaults.vaultId;
    	      this.vaultUri = defaults.vaultUri;
        }

        @CustomType.Setter
        public Builder arnRole(String arnRole) {
            if (arnRole == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "arnRole");
            }
            this.arnRole = arnRole;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousDatabasesCloneProvider(String autonomousDatabasesCloneProvider) {
            if (autonomousDatabasesCloneProvider == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "autonomousDatabasesCloneProvider");
            }
            this.autonomousDatabasesCloneProvider = autonomousDatabasesCloneProvider;
            return this;
        }
        @CustomType.Setter
        public Builder certificateDirectoryName(String certificateDirectoryName) {
            if (certificateDirectoryName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "certificateDirectoryName");
            }
            this.certificateDirectoryName = certificateDirectoryName;
            return this;
        }
        @CustomType.Setter
        public Builder certificateId(String certificateId) {
            if (certificateId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "certificateId");
            }
            this.certificateId = certificateId;
            return this;
        }
        @CustomType.Setter
        public Builder directoryName(String directoryName) {
            if (directoryName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "directoryName");
            }
            this.directoryName = directoryName;
            return this;
        }
        @CustomType.Setter
        public Builder externalId(String externalId) {
            if (externalId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "externalId");
            }
            this.externalId = externalId;
            return this;
        }
        @CustomType.Setter
        public Builder keyArn(String keyArn) {
            if (keyArn == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "keyArn");
            }
            this.keyArn = keyArn;
            return this;
        }
        @CustomType.Setter
        public Builder keyName(String keyName) {
            if (keyName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "keyName");
            }
            this.keyName = keyName;
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyId(String kmsKeyId) {
            if (kmsKeyId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "kmsKeyId");
            }
            this.kmsKeyId = kmsKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder okvKmsKey(String okvKmsKey) {
            if (okvKmsKey == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "okvKmsKey");
            }
            this.okvKmsKey = okvKmsKey;
            return this;
        }
        @CustomType.Setter
        public Builder okvUri(String okvUri) {
            if (okvUri == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "okvUri");
            }
            this.okvUri = okvUri;
            return this;
        }
        @CustomType.Setter
        public Builder serviceEndpointUri(String serviceEndpointUri) {
            if (serviceEndpointUri == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "serviceEndpointUri");
            }
            this.serviceEndpointUri = serviceEndpointUri;
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(String vaultId) {
            if (vaultId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "vaultId");
            }
            this.vaultId = vaultId;
            return this;
        }
        @CustomType.Setter
        public Builder vaultUri(String vaultUri) {
            if (vaultUri == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey", "vaultUri");
            }
            this.vaultUri = vaultUri;
            return this;
        }
        public GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey build() {
            final var _resultValue = new GetAutonomousDatabasesClonesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey();
            _resultValue.arnRole = arnRole;
            _resultValue.autonomousDatabasesCloneProvider = autonomousDatabasesCloneProvider;
            _resultValue.certificateDirectoryName = certificateDirectoryName;
            _resultValue.certificateId = certificateId;
            _resultValue.directoryName = directoryName;
            _resultValue.externalId = externalId;
            _resultValue.keyArn = keyArn;
            _resultValue.keyName = keyName;
            _resultValue.kmsKeyId = kmsKeyId;
            _resultValue.okvKmsKey = okvKmsKey;
            _resultValue.okvUri = okvUri;
            _resultValue.serviceEndpointUri = serviceEndpointUri;
            _resultValue.vaultId = vaultId;
            _resultValue.vaultUri = vaultUri;
            return _resultValue;
        }
    }
}
