// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedPreferredCredentialResult {
    /**
     * @return The name of the preferred credential.
     * 
     */
    private String credentialName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Indicates whether the preferred credential is accessible.
     * 
     */
    private Boolean isAccessible;
    private String managedDatabaseId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Vault service secret that contains the database user password.
     * 
     */
    private String passwordSecretId;
    /**
     * @return The role of the database user.
     * 
     */
    private String role;
    /**
     * @return The status of the preferred credential.
     * 
     */
    private String status;
    /**
     * @return The type of preferred credential. Only &#39;BASIC&#39; is supported currently.
     * 
     */
    private String type;
    /**
     * @return The user name used to connect to the database.
     * 
     */
    private String userName;

    private GetManagedPreferredCredentialResult() {}
    /**
     * @return The name of the preferred credential.
     * 
     */
    public String credentialName() {
        return this.credentialName;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether the preferred credential is accessible.
     * 
     */
    public Boolean isAccessible() {
        return this.isAccessible;
    }
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Vault service secret that contains the database user password.
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
     * @return The status of the preferred credential.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The type of preferred credential. Only &#39;BASIC&#39; is supported currently.
     * 
     */
    public String type() {
        return this.type;
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

    public static Builder builder(GetManagedPreferredCredentialResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String credentialName;
        private String id;
        private Boolean isAccessible;
        private String managedDatabaseId;
        private String passwordSecretId;
        private String role;
        private String status;
        private String type;
        private String userName;
        public Builder() {}
        public Builder(GetManagedPreferredCredentialResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credentialName = defaults.credentialName;
    	      this.id = defaults.id;
    	      this.isAccessible = defaults.isAccessible;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.passwordSecretId = defaults.passwordSecretId;
    	      this.role = defaults.role;
    	      this.status = defaults.status;
    	      this.type = defaults.type;
    	      this.userName = defaults.userName;
        }

        @CustomType.Setter
        public Builder credentialName(String credentialName) {
            this.credentialName = Objects.requireNonNull(credentialName);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isAccessible(Boolean isAccessible) {
            this.isAccessible = Objects.requireNonNull(isAccessible);
            return this;
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            this.managedDatabaseId = Objects.requireNonNull(managedDatabaseId);
            return this;
        }
        @CustomType.Setter
        public Builder passwordSecretId(String passwordSecretId) {
            this.passwordSecretId = Objects.requireNonNull(passwordSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder role(String role) {
            this.role = Objects.requireNonNull(role);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            this.userName = Objects.requireNonNull(userName);
            return this;
        }
        public GetManagedPreferredCredentialResult build() {
            final var o = new GetManagedPreferredCredentialResult();
            o.credentialName = credentialName;
            o.id = id;
            o.isAccessible = isAccessible;
            o.managedDatabaseId = managedDatabaseId;
            o.passwordSecretId = passwordSecretId;
            o.role = role;
            o.status = status;
            o.type = type;
            o.userName = userName;
            return o;
        }
    }
}