// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential {
    /**
     * @return The name of the credential information that used to connect to the database. The name should be in &#34;x.y&#34; format, where the length of &#34;x&#34; has a maximum of 64 characters, and length of &#34;y&#34; has a maximum of 199 characters. The name strings can contain letters, numbers and the underscore character only. Other characters are not valid, except for the &#34;.&#34; character that separates the &#34;x&#34; and &#34;y&#34; portions of the name. *IMPORTANT* - The name must be unique within the Oracle Cloud Infrastructure region the credential is being created in. If you specify a name that duplicates the name of another credential within the same Oracle Cloud Infrastructure region, you may overwrite or corrupt the credential that is already using the name.
     * 
     */
    private final String credentialName;
    /**
     * @return The type of credential used to connect to the database.
     * 
     */
    private final String credentialType;
    /**
     * @return The password that will be used to connect to the database.
     * 
     */
    private final String password;
    /**
     * @return The role of the user that will be connecting to the database.
     * 
     */
    private final String role;
    /**
     * @return The username that will be used to connect to the database.
     * 
     */
    private final String username;

    @CustomType.Constructor
    private GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential(
        @CustomType.Parameter("credentialName") String credentialName,
        @CustomType.Parameter("credentialType") String credentialType,
        @CustomType.Parameter("password") String password,
        @CustomType.Parameter("role") String role,
        @CustomType.Parameter("username") String username) {
        this.credentialName = credentialName;
        this.credentialType = credentialType;
        this.password = password;
        this.role = role;
        this.username = username;
    }

    /**
     * @return The name of the credential information that used to connect to the database. The name should be in &#34;x.y&#34; format, where the length of &#34;x&#34; has a maximum of 64 characters, and length of &#34;y&#34; has a maximum of 199 characters. The name strings can contain letters, numbers and the underscore character only. Other characters are not valid, except for the &#34;.&#34; character that separates the &#34;x&#34; and &#34;y&#34; portions of the name. *IMPORTANT* - The name must be unique within the Oracle Cloud Infrastructure region the credential is being created in. If you specify a name that duplicates the name of another credential within the same Oracle Cloud Infrastructure region, you may overwrite or corrupt the credential that is already using the name.
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
     * @return The password that will be used to connect to the database.
     * 
     */
    public String password() {
        return this.password;
    }
    /**
     * @return The role of the user that will be connecting to the database.
     * 
     */
    public String role() {
        return this.role;
    }
    /**
     * @return The username that will be used to connect to the database.
     * 
     */
    public String username() {
        return this.username;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String credentialName;
        private String credentialType;
        private String password;
        private String role;
        private String username;

        public Builder() {
    	      // Empty
        }

        public Builder(GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credentialName = defaults.credentialName;
    	      this.credentialType = defaults.credentialType;
    	      this.password = defaults.password;
    	      this.role = defaults.role;
    	      this.username = defaults.username;
        }

        public Builder credentialName(String credentialName) {
            this.credentialName = Objects.requireNonNull(credentialName);
            return this;
        }
        public Builder credentialType(String credentialType) {
            this.credentialType = Objects.requireNonNull(credentialType);
            return this;
        }
        public Builder password(String password) {
            this.password = Objects.requireNonNull(password);
            return this;
        }
        public Builder role(String role) {
            this.role = Objects.requireNonNull(role);
            return this;
        }
        public Builder username(String username) {
            this.username = Objects.requireNonNull(username);
            return this;
        }        public GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential build() {
            return new GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential(credentialName, credentialType, password, role, username);
        }
    }
}
