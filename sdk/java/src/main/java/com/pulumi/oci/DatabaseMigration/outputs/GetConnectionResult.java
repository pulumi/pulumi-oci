// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetConnectionAdminCredential;
import com.pulumi.oci.DatabaseMigration.outputs.GetConnectionConnectDescriptor;
import com.pulumi.oci.DatabaseMigration.outputs.GetConnectionPrivateEndpoint;
import com.pulumi.oci.DatabaseMigration.outputs.GetConnectionSshDetail;
import com.pulumi.oci.DatabaseMigration.outputs.GetConnectionVaultDetail;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetConnectionResult {
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    private List<GetConnectionAdminCredential> adminCredentials;
    /**
     * @return This name is the distinguished name used while creating the certificate on target database.
     * 
     */
    private String certificateTdn;
    /**
     * @return OCID of the compartment where the secret containing the credentials will be created.
     * 
     */
    private String compartmentId;
    /**
     * @return Connect Descriptor details.
     * 
     */
    private List<GetConnectionConnectDescriptor> connectDescriptors;
    private String connectionId;
    /**
     * @return OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Database Connection credentials.
     * 
     */
    private String credentialsSecretId;
    /**
     * @return The OCID of the cloud database.
     * 
     */
    private String databaseId;
    /**
     * @return Database connection type.
     * 
     */
    private String databaseType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Database Connection display name identifier.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a previously created Private Endpoint.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Oracle Cloud Infrastructure Private Endpoint configuration details.
     * 
     */
    private List<GetConnectionPrivateEndpoint> privateEndpoints;
    /**
     * @return Details of the SSH key that will be used.
     * 
     */
    private List<GetConnectionSshDetail> sshDetails;
    /**
     * @return The current state of the Connection resource.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the Connection resource was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time of the last Connection resource details update. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    private String tlsKeystore;
    private String tlsWallet;
    /**
     * @return Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     * 
     */
    private List<GetConnectionVaultDetail> vaultDetails;

    private GetConnectionResult() {}
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    public List<GetConnectionAdminCredential> adminCredentials() {
        return this.adminCredentials;
    }
    /**
     * @return This name is the distinguished name used while creating the certificate on target database.
     * 
     */
    public String certificateTdn() {
        return this.certificateTdn;
    }
    /**
     * @return OCID of the compartment where the secret containing the credentials will be created.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Connect Descriptor details.
     * 
     */
    public List<GetConnectionConnectDescriptor> connectDescriptors() {
        return this.connectDescriptors;
    }
    public String connectionId() {
        return this.connectionId;
    }
    /**
     * @return OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Database Connection credentials.
     * 
     */
    public String credentialsSecretId() {
        return this.credentialsSecretId;
    }
    /**
     * @return The OCID of the cloud database.
     * 
     */
    public String databaseId() {
        return this.databaseId;
    }
    /**
     * @return Database connection type.
     * 
     */
    public String databaseType() {
        return this.databaseType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Database Connection display name identifier.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a previously created Private Endpoint.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Oracle Cloud Infrastructure Private Endpoint configuration details.
     * 
     */
    public List<GetConnectionPrivateEndpoint> privateEndpoints() {
        return this.privateEndpoints;
    }
    /**
     * @return Details of the SSH key that will be used.
     * 
     */
    public List<GetConnectionSshDetail> sshDetails() {
        return this.sshDetails;
    }
    /**
     * @return The current state of the Connection resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the Connection resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time of the last Connection resource details update. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    public String tlsKeystore() {
        return this.tlsKeystore;
    }
    public String tlsWallet() {
        return this.tlsWallet;
    }
    /**
     * @return Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     * 
     */
    public List<GetConnectionVaultDetail> vaultDetails() {
        return this.vaultDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConnectionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetConnectionAdminCredential> adminCredentials;
        private String certificateTdn;
        private String compartmentId;
        private List<GetConnectionConnectDescriptor> connectDescriptors;
        private String connectionId;
        private String credentialsSecretId;
        private String databaseId;
        private String databaseType;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private List<GetConnectionPrivateEndpoint> privateEndpoints;
        private List<GetConnectionSshDetail> sshDetails;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String tlsKeystore;
        private String tlsWallet;
        private List<GetConnectionVaultDetail> vaultDetails;
        public Builder() {}
        public Builder(GetConnectionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminCredentials = defaults.adminCredentials;
    	      this.certificateTdn = defaults.certificateTdn;
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectDescriptors = defaults.connectDescriptors;
    	      this.connectionId = defaults.connectionId;
    	      this.credentialsSecretId = defaults.credentialsSecretId;
    	      this.databaseId = defaults.databaseId;
    	      this.databaseType = defaults.databaseType;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.privateEndpoints = defaults.privateEndpoints;
    	      this.sshDetails = defaults.sshDetails;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.tlsKeystore = defaults.tlsKeystore;
    	      this.tlsWallet = defaults.tlsWallet;
    	      this.vaultDetails = defaults.vaultDetails;
        }

        @CustomType.Setter
        public Builder adminCredentials(List<GetConnectionAdminCredential> adminCredentials) {
            this.adminCredentials = Objects.requireNonNull(adminCredentials);
            return this;
        }
        public Builder adminCredentials(GetConnectionAdminCredential... adminCredentials) {
            return adminCredentials(List.of(adminCredentials));
        }
        @CustomType.Setter
        public Builder certificateTdn(String certificateTdn) {
            this.certificateTdn = Objects.requireNonNull(certificateTdn);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder connectDescriptors(List<GetConnectionConnectDescriptor> connectDescriptors) {
            this.connectDescriptors = Objects.requireNonNull(connectDescriptors);
            return this;
        }
        public Builder connectDescriptors(GetConnectionConnectDescriptor... connectDescriptors) {
            return connectDescriptors(List.of(connectDescriptors));
        }
        @CustomType.Setter
        public Builder connectionId(String connectionId) {
            this.connectionId = Objects.requireNonNull(connectionId);
            return this;
        }
        @CustomType.Setter
        public Builder credentialsSecretId(String credentialsSecretId) {
            this.credentialsSecretId = Objects.requireNonNull(credentialsSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder databaseId(String databaseId) {
            this.databaseId = Objects.requireNonNull(databaseId);
            return this;
        }
        @CustomType.Setter
        public Builder databaseType(String databaseType) {
            this.databaseType = Objects.requireNonNull(databaseType);
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
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpoints(List<GetConnectionPrivateEndpoint> privateEndpoints) {
            this.privateEndpoints = Objects.requireNonNull(privateEndpoints);
            return this;
        }
        public Builder privateEndpoints(GetConnectionPrivateEndpoint... privateEndpoints) {
            return privateEndpoints(List.of(privateEndpoints));
        }
        @CustomType.Setter
        public Builder sshDetails(List<GetConnectionSshDetail> sshDetails) {
            this.sshDetails = Objects.requireNonNull(sshDetails);
            return this;
        }
        public Builder sshDetails(GetConnectionSshDetail... sshDetails) {
            return sshDetails(List.of(sshDetails));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder tlsKeystore(String tlsKeystore) {
            this.tlsKeystore = Objects.requireNonNull(tlsKeystore);
            return this;
        }
        @CustomType.Setter
        public Builder tlsWallet(String tlsWallet) {
            this.tlsWallet = Objects.requireNonNull(tlsWallet);
            return this;
        }
        @CustomType.Setter
        public Builder vaultDetails(List<GetConnectionVaultDetail> vaultDetails) {
            this.vaultDetails = Objects.requireNonNull(vaultDetails);
            return this;
        }
        public Builder vaultDetails(GetConnectionVaultDetail... vaultDetails) {
            return vaultDetails(List.of(vaultDetails));
        }
        public GetConnectionResult build() {
            final var o = new GetConnectionResult();
            o.adminCredentials = adminCredentials;
            o.certificateTdn = certificateTdn;
            o.compartmentId = compartmentId;
            o.connectDescriptors = connectDescriptors;
            o.connectionId = connectionId;
            o.credentialsSecretId = credentialsSecretId;
            o.databaseId = databaseId;
            o.databaseType = databaseType;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.privateEndpoints = privateEndpoints;
            o.sshDetails = sshDetails;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.tlsKeystore = tlsKeystore;
            o.tlsWallet = tlsWallet;
            o.vaultDetails = vaultDetails;
            return o;
        }
    }
}