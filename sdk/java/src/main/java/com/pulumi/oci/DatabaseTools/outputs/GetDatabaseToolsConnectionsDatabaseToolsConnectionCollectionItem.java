// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStore;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemRelatedResource;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemUserPassword;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem {
    /**
     * @return The advanced connection properties key-value pair (for example, `oracle.net.ssl_server_dn_match`).
     * 
     */
    private Map<String,Object> advancedProperties;
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return The connect descriptor or Easy Connect Naming method used to connect to the database.
     * 
     */
    private String connectionString;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the entire specified display name.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools connection.
     * 
     */
    private String id;
    /**
     * @return The Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
     * 
     */
    private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStore> keyStores;
    /**
     * @return A message describing the current state in more detail. For example, this message can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
     * 
     */
    private String privateEndpointId;
    /**
     * @return A related resource
     * 
     */
    private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemRelatedResource> relatedResources;
    /**
     * @return A filter to return only resources their `lifecycleState` matches the specified `lifecycleState`.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the Database Tools connection was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the DatabaseToolsConnection was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    /**
     * @return A filter to return only resources their type matches the specified type.
     * 
     */
    private String type;
    /**
     * @return The database user name.
     * 
     */
    private String userName;
    /**
     * @return The user password.
     * 
     */
    private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemUserPassword> userPasswords;

    private GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem() {}
    /**
     * @return The advanced connection properties key-value pair (for example, `oracle.net.ssl_server_dn_match`).
     * 
     */
    public Map<String,Object> advancedProperties() {
        return this.advancedProperties;
    }
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The connect descriptor or Easy Connect Naming method used to connect to the database.
     * 
     */
    public String connectionString() {
        return this.connectionString;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the entire specified display name.
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools connection.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
     * 
     */
    public List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStore> keyStores() {
        return this.keyStores;
    }
    /**
     * @return A message describing the current state in more detail. For example, this message can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
     * 
     */
    public String privateEndpointId() {
        return this.privateEndpointId;
    }
    /**
     * @return A related resource
     * 
     */
    public List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemRelatedResource> relatedResources() {
        return this.relatedResources;
    }
    /**
     * @return A filter to return only resources their `lifecycleState` matches the specified `lifecycleState`.
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
     * @return The time the Database Tools connection was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the DatabaseToolsConnection was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return A filter to return only resources their type matches the specified type.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The database user name.
     * 
     */
    public String userName() {
        return this.userName;
    }
    /**
     * @return The user password.
     * 
     */
    public List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemUserPassword> userPasswords() {
        return this.userPasswords;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,Object> advancedProperties;
        private String compartmentId;
        private String connectionString;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStore> keyStores;
        private String lifecycleDetails;
        private String privateEndpointId;
        private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemRelatedResource> relatedResources;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String type;
        private String userName;
        private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemUserPassword> userPasswords;
        public Builder() {}
        public Builder(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advancedProperties = defaults.advancedProperties;
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionString = defaults.connectionString;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.keyStores = defaults.keyStores;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.privateEndpointId = defaults.privateEndpointId;
    	      this.relatedResources = defaults.relatedResources;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.type = defaults.type;
    	      this.userName = defaults.userName;
    	      this.userPasswords = defaults.userPasswords;
        }

        @CustomType.Setter
        public Builder advancedProperties(Map<String,Object> advancedProperties) {
            this.advancedProperties = Objects.requireNonNull(advancedProperties);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder connectionString(String connectionString) {
            this.connectionString = Objects.requireNonNull(connectionString);
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
        public Builder keyStores(List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStore> keyStores) {
            this.keyStores = Objects.requireNonNull(keyStores);
            return this;
        }
        public Builder keyStores(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStore... keyStores) {
            return keyStores(List.of(keyStores));
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointId(String privateEndpointId) {
            this.privateEndpointId = Objects.requireNonNull(privateEndpointId);
            return this;
        }
        @CustomType.Setter
        public Builder relatedResources(List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemRelatedResource> relatedResources) {
            this.relatedResources = Objects.requireNonNull(relatedResources);
            return this;
        }
        public Builder relatedResources(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemRelatedResource... relatedResources) {
            return relatedResources(List.of(relatedResources));
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
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            this.userName = Objects.requireNonNull(userName);
            return this;
        }
        @CustomType.Setter
        public Builder userPasswords(List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemUserPassword> userPasswords) {
            this.userPasswords = Objects.requireNonNull(userPasswords);
            return this;
        }
        public Builder userPasswords(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemUserPassword... userPasswords) {
            return userPasswords(List.of(userPasswords));
        }
        public GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem build() {
            final var o = new GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem();
            o.advancedProperties = advancedProperties;
            o.compartmentId = compartmentId;
            o.connectionString = connectionString;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.keyStores = keyStores;
            o.lifecycleDetails = lifecycleDetails;
            o.privateEndpointId = privateEndpointId;
            o.relatedResources = relatedResources;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.type = type;
            o.userName = userName;
            o.userPasswords = userPasswords;
            return o;
        }
    }
}