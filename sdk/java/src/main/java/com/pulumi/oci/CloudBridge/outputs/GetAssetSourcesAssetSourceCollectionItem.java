// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudBridge.outputs.GetAssetSourcesAssetSourceCollectionItemDiscoveryCredential;
import com.pulumi.oci.CloudBridge.outputs.GetAssetSourcesAssetSourceCollectionItemReplicationCredential;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAssetSourcesAssetSourceCollectionItem {
    /**
     * @return Flag indicating whether historical metrics are collected for assets, originating from this asset source.
     * 
     */
    private Boolean areHistoricalMetricsCollected;
    /**
     * @return Flag indicating whether real-time metrics are collected for assets, originating from this asset source.
     * 
     */
    private Boolean areRealtimeMetricsCollected;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that is going to be used to create assets.
     * 
     */
    private String assetsCompartmentId;
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Credentials for an asset source.
     * 
     */
    private List<GetAssetSourcesAssetSourceCollectionItemDiscoveryCredential> discoveryCredentials;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an attached discovery schedule.
     * 
     */
    private String discoveryScheduleId;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the environment.
     * 
     */
    private String environmentId;
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the inventory that will contain created assets.
     * 
     */
    private String inventoryId;
    /**
     * @return The detailed state of the asset source.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Credentials for an asset source.
     * 
     */
    private List<GetAssetSourcesAssetSourceCollectionItemReplicationCredential> replicationCredentials;
    /**
     * @return The current state of the asset source.
     * 
     */
    private String state;
    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time when the asset source was created in the RFC3339 format.
     * 
     */
    private String timeCreated;
    /**
     * @return The point in time that the asset source was last updated in the RFC3339 format.
     * 
     */
    private String timeUpdated;
    /**
     * @return The type of asset source. Indicates external origin of the assets that are read by assigning this asset source.
     * 
     */
    private String type;
    /**
     * @return Endpoint for VMware asset discovery and replication in the form of ```https://&lt;host&gt;:&lt;port&gt;/sdk```
     * 
     */
    private String vcenterEndpoint;

    private GetAssetSourcesAssetSourceCollectionItem() {}
    /**
     * @return Flag indicating whether historical metrics are collected for assets, originating from this asset source.
     * 
     */
    public Boolean areHistoricalMetricsCollected() {
        return this.areHistoricalMetricsCollected;
    }
    /**
     * @return Flag indicating whether real-time metrics are collected for assets, originating from this asset source.
     * 
     */
    public Boolean areRealtimeMetricsCollected() {
        return this.areRealtimeMetricsCollected;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that is going to be used to create assets.
     * 
     */
    public String assetsCompartmentId() {
        return this.assetsCompartmentId;
    }
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Credentials for an asset source.
     * 
     */
    public List<GetAssetSourcesAssetSourceCollectionItemDiscoveryCredential> discoveryCredentials() {
        return this.discoveryCredentials;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an attached discovery schedule.
     * 
     */
    public String discoveryScheduleId() {
        return this.discoveryScheduleId;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the environment.
     * 
     */
    public String environmentId() {
        return this.environmentId;
    }
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the inventory that will contain created assets.
     * 
     */
    public String inventoryId() {
        return this.inventoryId;
    }
    /**
     * @return The detailed state of the asset source.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Credentials for an asset source.
     * 
     */
    public List<GetAssetSourcesAssetSourceCollectionItemReplicationCredential> replicationCredentials() {
        return this.replicationCredentials;
    }
    /**
     * @return The current state of the asset source.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time when the asset source was created in the RFC3339 format.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The point in time that the asset source was last updated in the RFC3339 format.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The type of asset source. Indicates external origin of the assets that are read by assigning this asset source.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Endpoint for VMware asset discovery and replication in the form of ```https://&lt;host&gt;:&lt;port&gt;/sdk```
     * 
     */
    public String vcenterEndpoint() {
        return this.vcenterEndpoint;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssetSourcesAssetSourceCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean areHistoricalMetricsCollected;
        private Boolean areRealtimeMetricsCollected;
        private String assetsCompartmentId;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private List<GetAssetSourcesAssetSourceCollectionItemDiscoveryCredential> discoveryCredentials;
        private String discoveryScheduleId;
        private String displayName;
        private String environmentId;
        private Map<String,Object> freeformTags;
        private String id;
        private String inventoryId;
        private String lifecycleDetails;
        private List<GetAssetSourcesAssetSourceCollectionItemReplicationCredential> replicationCredentials;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String type;
        private String vcenterEndpoint;
        public Builder() {}
        public Builder(GetAssetSourcesAssetSourceCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.areHistoricalMetricsCollected = defaults.areHistoricalMetricsCollected;
    	      this.areRealtimeMetricsCollected = defaults.areRealtimeMetricsCollected;
    	      this.assetsCompartmentId = defaults.assetsCompartmentId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.discoveryCredentials = defaults.discoveryCredentials;
    	      this.discoveryScheduleId = defaults.discoveryScheduleId;
    	      this.displayName = defaults.displayName;
    	      this.environmentId = defaults.environmentId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.inventoryId = defaults.inventoryId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.replicationCredentials = defaults.replicationCredentials;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.type = defaults.type;
    	      this.vcenterEndpoint = defaults.vcenterEndpoint;
        }

        @CustomType.Setter
        public Builder areHistoricalMetricsCollected(Boolean areHistoricalMetricsCollected) {
            this.areHistoricalMetricsCollected = Objects.requireNonNull(areHistoricalMetricsCollected);
            return this;
        }
        @CustomType.Setter
        public Builder areRealtimeMetricsCollected(Boolean areRealtimeMetricsCollected) {
            this.areRealtimeMetricsCollected = Objects.requireNonNull(areRealtimeMetricsCollected);
            return this;
        }
        @CustomType.Setter
        public Builder assetsCompartmentId(String assetsCompartmentId) {
            this.assetsCompartmentId = Objects.requireNonNull(assetsCompartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder discoveryCredentials(List<GetAssetSourcesAssetSourceCollectionItemDiscoveryCredential> discoveryCredentials) {
            this.discoveryCredentials = Objects.requireNonNull(discoveryCredentials);
            return this;
        }
        public Builder discoveryCredentials(GetAssetSourcesAssetSourceCollectionItemDiscoveryCredential... discoveryCredentials) {
            return discoveryCredentials(List.of(discoveryCredentials));
        }
        @CustomType.Setter
        public Builder discoveryScheduleId(String discoveryScheduleId) {
            this.discoveryScheduleId = Objects.requireNonNull(discoveryScheduleId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder environmentId(String environmentId) {
            this.environmentId = Objects.requireNonNull(environmentId);
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
        public Builder inventoryId(String inventoryId) {
            this.inventoryId = Objects.requireNonNull(inventoryId);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder replicationCredentials(List<GetAssetSourcesAssetSourceCollectionItemReplicationCredential> replicationCredentials) {
            this.replicationCredentials = Objects.requireNonNull(replicationCredentials);
            return this;
        }
        public Builder replicationCredentials(GetAssetSourcesAssetSourceCollectionItemReplicationCredential... replicationCredentials) {
            return replicationCredentials(List.of(replicationCredentials));
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
        public Builder vcenterEndpoint(String vcenterEndpoint) {
            this.vcenterEndpoint = Objects.requireNonNull(vcenterEndpoint);
            return this;
        }
        public GetAssetSourcesAssetSourceCollectionItem build() {
            final var o = new GetAssetSourcesAssetSourceCollectionItem();
            o.areHistoricalMetricsCollected = areHistoricalMetricsCollected;
            o.areRealtimeMetricsCollected = areRealtimeMetricsCollected;
            o.assetsCompartmentId = assetsCompartmentId;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.discoveryCredentials = discoveryCredentials;
            o.discoveryScheduleId = discoveryScheduleId;
            o.displayName = displayName;
            o.environmentId = environmentId;
            o.freeformTags = freeformTags;
            o.id = id;
            o.inventoryId = inventoryId;
            o.lifecycleDetails = lifecycleDetails;
            o.replicationCredentials = replicationCredentials;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.type = type;
            o.vcenterEndpoint = vcenterEndpoint;
            return o;
        }
    }
}