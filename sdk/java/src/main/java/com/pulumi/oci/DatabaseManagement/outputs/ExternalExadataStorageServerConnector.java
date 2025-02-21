// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExternalExadataStorageServerConnector {
    /**
     * @return The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,String> additionalDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
     * 
     */
    private @Nullable String agentId;
    /**
     * @return The unique string of the connection. For example, &#34;https://&lt;storage-server-name&gt;/MS/RESTService/&#34;.
     * 
     */
    private @Nullable String connectionUri;
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private @Nullable Map<String,String> definedTags;
    /**
     * @return The name of the Exadata resource. English letters, numbers, &#34;-&#34;, &#34;_&#34; and &#34;.&#34; only.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private @Nullable Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
     * 
     */
    private @Nullable String id;
    /**
     * @return The internal ID of the Exadata resource.
     * 
     */
    private @Nullable String internalId;
    /**
     * @return The details of the lifecycle state of the Exadata resource.
     * 
     */
    private @Nullable String lifecycleDetails;
    /**
     * @return The type of Exadata resource.
     * 
     */
    private @Nullable String resourceType;
    /**
     * @return The current lifecycle state of the database resource.
     * 
     */
    private @Nullable String state;
    /**
     * @return The status of the Exadata resource.
     * 
     */
    private @Nullable String status;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
     * 
     */
    private @Nullable String storageServerId;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private @Nullable Map<String,String> systemTags;
    /**
     * @return The timestamp of the creation of the Exadata resource.
     * 
     */
    private @Nullable String timeCreated;
    /**
     * @return The timestamp of the last update of the Exadata resource.
     * 
     */
    private @Nullable String timeUpdated;
    /**
     * @return The version of the Exadata resource.
     * 
     */
    private @Nullable String version;

    private ExternalExadataStorageServerConnector() {}
    /**
     * @return The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> additionalDetails() {
        return this.additionalDetails == null ? Map.of() : this.additionalDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
     * 
     */
    public Optional<String> agentId() {
        return Optional.ofNullable(this.agentId);
    }
    /**
     * @return The unique string of the connection. For example, &#34;https://&lt;storage-server-name&gt;/MS/RESTService/&#34;.
     * 
     */
    public Optional<String> connectionUri() {
        return Optional.ofNullable(this.connectionUri);
    }
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return The name of the Exadata resource. English letters, numbers, &#34;-&#34;, &#34;_&#34; and &#34;.&#34; only.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The internal ID of the Exadata resource.
     * 
     */
    public Optional<String> internalId() {
        return Optional.ofNullable(this.internalId);
    }
    /**
     * @return The details of the lifecycle state of the Exadata resource.
     * 
     */
    public Optional<String> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }
    /**
     * @return The type of Exadata resource.
     * 
     */
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }
    /**
     * @return The current lifecycle state of the database resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The status of the Exadata resource.
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
     * 
     */
    public Optional<String> storageServerId() {
        return Optional.ofNullable(this.storageServerId);
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags == null ? Map.of() : this.systemTags;
    }
    /**
     * @return The timestamp of the creation of the Exadata resource.
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }
    /**
     * @return The timestamp of the last update of the Exadata resource.
     * 
     */
    public Optional<String> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }
    /**
     * @return The version of the Exadata resource.
     * 
     */
    public Optional<String> version() {
        return Optional.ofNullable(this.version);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExternalExadataStorageServerConnector defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,String> additionalDetails;
        private @Nullable String agentId;
        private @Nullable String connectionUri;
        private @Nullable Map<String,String> definedTags;
        private @Nullable String displayName;
        private @Nullable Map<String,String> freeformTags;
        private @Nullable String id;
        private @Nullable String internalId;
        private @Nullable String lifecycleDetails;
        private @Nullable String resourceType;
        private @Nullable String state;
        private @Nullable String status;
        private @Nullable String storageServerId;
        private @Nullable Map<String,String> systemTags;
        private @Nullable String timeCreated;
        private @Nullable String timeUpdated;
        private @Nullable String version;
        public Builder() {}
        public Builder(ExternalExadataStorageServerConnector defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalDetails = defaults.additionalDetails;
    	      this.agentId = defaults.agentId;
    	      this.connectionUri = defaults.connectionUri;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.internalId = defaults.internalId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.resourceType = defaults.resourceType;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.storageServerId = defaults.storageServerId;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder additionalDetails(@Nullable Map<String,String> additionalDetails) {

            this.additionalDetails = additionalDetails;
            return this;
        }
        @CustomType.Setter
        public Builder agentId(@Nullable String agentId) {

            this.agentId = agentId;
            return this;
        }
        @CustomType.Setter
        public Builder connectionUri(@Nullable String connectionUri) {

            this.connectionUri = connectionUri;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,String> definedTags) {

            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,String> freeformTags) {

            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder internalId(@Nullable String internalId) {

            this.internalId = internalId;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {

            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(@Nullable String resourceType) {

            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder status(@Nullable String status) {

            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder storageServerId(@Nullable String storageServerId) {

            this.storageServerId = storageServerId;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(@Nullable Map<String,String> systemTags) {

            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(@Nullable String timeCreated) {

            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(@Nullable String timeUpdated) {

            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder version(@Nullable String version) {

            this.version = version;
            return this;
        }
        public ExternalExadataStorageServerConnector build() {
            final var _resultValue = new ExternalExadataStorageServerConnector();
            _resultValue.additionalDetails = additionalDetails;
            _resultValue.agentId = agentId;
            _resultValue.connectionUri = connectionUri;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.internalId = internalId;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.resourceType = resourceType;
            _resultValue.state = state;
            _resultValue.status = status;
            _resultValue.storageServerId = storageServerId;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
