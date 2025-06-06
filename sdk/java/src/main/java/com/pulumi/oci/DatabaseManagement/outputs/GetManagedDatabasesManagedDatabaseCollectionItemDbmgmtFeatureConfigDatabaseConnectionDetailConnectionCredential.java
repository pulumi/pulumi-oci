// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential {
    /**
     * @return The name of the credential information that used to connect to the DB system resource. The name should be in &#34;x.y&#34; format, where the length of &#34;x&#34; has a maximum of 64 characters, and length of &#34;y&#34; has a maximum of 199 characters. The name strings can contain letters, numbers and the underscore character only. Other characters are not valid, except for the &#34;.&#34; character that separates the &#34;x&#34; and &#34;y&#34; portions of the name. *IMPORTANT* - The name must be unique within the Oracle Cloud Infrastructure region the credential is being created in. If you specify a name that duplicates the name of another credential within the same Oracle Cloud Infrastructure region, you may overwrite or corrupt the credential that is already using the name.
     * 
     */
    private String credentialName;
    /**
     * @return The type of credential used to connect to the database.
     * 
     */
    private String credentialType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Named Credential where the database password metadata is stored.
     * 
     */
    private String namedCredentialId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
     * 
     */
    private String passwordSecretId;
    /**
     * @return The role of the user connecting to the database.
     * 
     */
    private String role;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the SSL keystore and truststore details.
     * 
     */
    private String sslSecretId;
    /**
     * @return The user name used to connect to the database.
     * 
     */
    private String userName;

    private GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential() {}
    /**
     * @return The name of the credential information that used to connect to the DB system resource. The name should be in &#34;x.y&#34; format, where the length of &#34;x&#34; has a maximum of 64 characters, and length of &#34;y&#34; has a maximum of 199 characters. The name strings can contain letters, numbers and the underscore character only. Other characters are not valid, except for the &#34;.&#34; character that separates the &#34;x&#34; and &#34;y&#34; portions of the name. *IMPORTANT* - The name must be unique within the Oracle Cloud Infrastructure region the credential is being created in. If you specify a name that duplicates the name of another credential within the same Oracle Cloud Infrastructure region, you may overwrite or corrupt the credential that is already using the name.
     * 
     */
    public String credentialName() {
        return this.credentialName;
    }
    /**
     * @return The type of credential used to connect to the database.
     * 
     */
    public String credentialType() {
        return this.credentialType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Named Credential where the database password metadata is stored.
     * 
     */
    public String namedCredentialId() {
        return this.namedCredentialId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
     * 
     */
    public String passwordSecretId() {
        return this.passwordSecretId;
    }
    /**
     * @return The role of the user connecting to the database.
     * 
     */
    public String role() {
        return this.role;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the SSL keystore and truststore details.
     * 
     */
    public String sslSecretId() {
        return this.sslSecretId;
    }
    /**
     * @return The user name used to connect to the database.
     * 
     */
    public String userName() {
        return this.userName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String credentialName;
        private String credentialType;
        private String namedCredentialId;
        private String passwordSecretId;
        private String role;
        private String sslSecretId;
        private String userName;
        public Builder() {}
        public Builder(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credentialName = defaults.credentialName;
    	      this.credentialType = defaults.credentialType;
    	      this.namedCredentialId = defaults.namedCredentialId;
    	      this.passwordSecretId = defaults.passwordSecretId;
    	      this.role = defaults.role;
    	      this.sslSecretId = defaults.sslSecretId;
    	      this.userName = defaults.userName;
        }

        @CustomType.Setter
        public Builder credentialName(String credentialName) {
            if (credentialName == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential", "credentialName");
            }
            this.credentialName = credentialName;
            return this;
        }
        @CustomType.Setter
        public Builder credentialType(String credentialType) {
            if (credentialType == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential", "credentialType");
            }
            this.credentialType = credentialType;
            return this;
        }
        @CustomType.Setter
        public Builder namedCredentialId(String namedCredentialId) {
            if (namedCredentialId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential", "namedCredentialId");
            }
            this.namedCredentialId = namedCredentialId;
            return this;
        }
        @CustomType.Setter
        public Builder passwordSecretId(String passwordSecretId) {
            if (passwordSecretId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential", "passwordSecretId");
            }
            this.passwordSecretId = passwordSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder role(String role) {
            if (role == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential", "role");
            }
            this.role = role;
            return this;
        }
        @CustomType.Setter
        public Builder sslSecretId(String sslSecretId) {
            if (sslSecretId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential", "sslSecretId");
            }
            this.sslSecretId = sslSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            if (userName == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential", "userName");
            }
            this.userName = userName;
            return this;
        }
        public GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential build() {
            final var _resultValue = new GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetailConnectionCredential();
            _resultValue.credentialName = credentialName;
            _resultValue.credentialType = credentialType;
            _resultValue.namedCredentialId = namedCredentialId;
            _resultValue.passwordSecretId = passwordSecretId;
            _resultValue.role = role;
            _resultValue.sslSecretId = sslSecretId;
            _resultValue.userName = userName;
            return _resultValue;
        }
    }
}
