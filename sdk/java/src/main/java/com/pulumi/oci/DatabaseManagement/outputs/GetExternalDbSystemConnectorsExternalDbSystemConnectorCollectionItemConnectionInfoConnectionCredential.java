// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential {
    /**
     * @return The name of the credential information that used to connect to the DB system resource. The name should be in &#34;x.y&#34; format, where the length of &#34;x&#34; has a maximum of 64 characters, and length of &#34;y&#34; has a maximum of 199 characters. The name strings can contain letters, numbers and the underscore character only. Other characters are not valid, except for the &#34;.&#34; character that separates the &#34;x&#34; and &#34;y&#34; portions of the name. *IMPORTANT* - The name must be unique within the Oracle Cloud Infrastructure region the credential is being created in. If you specify a name that duplicates the name of another credential within the same Oracle Cloud Infrastructure region, you may overwrite or corrupt the credential that is already using the name.
     * 
     */
    private String credentialName;
    /**
     * @return The type of the credential for tablespace administration tasks.
     * 
     */
    private String credentialType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the named credential where the database password metadata is stored.
     * 
     */
    private String namedCredentialId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret where the database password is stored.
     * 
     */
    private String passwordSecretId;
    /**
     * @return The role of the database user.
     * 
     */
    private String role;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the SSL keystore and truststore details.
     * 
     */
    private String sslSecretId;
    /**
     * @return The user name used to connect to the ASM instance.
     * 
     */
    private String userName;

    private GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential() {}
    /**
     * @return The name of the credential information that used to connect to the DB system resource. The name should be in &#34;x.y&#34; format, where the length of &#34;x&#34; has a maximum of 64 characters, and length of &#34;y&#34; has a maximum of 199 characters. The name strings can contain letters, numbers and the underscore character only. Other characters are not valid, except for the &#34;.&#34; character that separates the &#34;x&#34; and &#34;y&#34; portions of the name. *IMPORTANT* - The name must be unique within the Oracle Cloud Infrastructure region the credential is being created in. If you specify a name that duplicates the name of another credential within the same Oracle Cloud Infrastructure region, you may overwrite or corrupt the credential that is already using the name.
     * 
     */
    public String credentialName() {
        return this.credentialName;
    }
    /**
     * @return The type of the credential for tablespace administration tasks.
     * 
     */
    public String credentialType() {
        return this.credentialType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the named credential where the database password metadata is stored.
     * 
     */
    public String namedCredentialId() {
        return this.namedCredentialId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret where the database password is stored.
     * 
     */
    public String passwordSecretId() {
        return this.passwordSecretId;
    }
    /**
     * @return The role of the database user.
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
     * @return The user name used to connect to the ASM instance.
     * 
     */
    public String userName() {
        return this.userName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential defaults) {
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
        public Builder(GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential defaults) {
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
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential", "credentialName");
            }
            this.credentialName = credentialName;
            return this;
        }
        @CustomType.Setter
        public Builder credentialType(String credentialType) {
            if (credentialType == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential", "credentialType");
            }
            this.credentialType = credentialType;
            return this;
        }
        @CustomType.Setter
        public Builder namedCredentialId(String namedCredentialId) {
            if (namedCredentialId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential", "namedCredentialId");
            }
            this.namedCredentialId = namedCredentialId;
            return this;
        }
        @CustomType.Setter
        public Builder passwordSecretId(String passwordSecretId) {
            if (passwordSecretId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential", "passwordSecretId");
            }
            this.passwordSecretId = passwordSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder role(String role) {
            if (role == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential", "role");
            }
            this.role = role;
            return this;
        }
        @CustomType.Setter
        public Builder sslSecretId(String sslSecretId) {
            if (sslSecretId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential", "sslSecretId");
            }
            this.sslSecretId = sslSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            if (userName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential", "userName");
            }
            this.userName = userName;
            return this;
        }
        public GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential build() {
            final var _resultValue = new GetExternalDbSystemConnectorsExternalDbSystemConnectorCollectionItemConnectionInfoConnectionCredential();
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
