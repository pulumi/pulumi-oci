// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MediaServices.outputs.GetStreamDistributionChannelsStreamDistributionChannelCollectionItemLock;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetStreamDistributionChannelsStreamDistributionChannelCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A filter to return only the resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Unique domain name of the Distribution Channel.
     * 
     */
    private String domainName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Unique Stream Distribution Channel identifier.
     * 
     */
    private String id;
    private Boolean isLockOverride;
    /**
     * @return Locks associated with this resource.
     * 
     */
    private List<GetStreamDistributionChannelsStreamDistributionChannelCollectionItemLock> locks;
    /**
     * @return A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time when the Stream Distribution Channel was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time when the Stream Distribution Channel was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetStreamDistributionChannelsStreamDistributionChannelCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only the resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Unique domain name of the Distribution Channel.
     * 
     */
    public String domainName() {
        return this.domainName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unique Stream Distribution Channel identifier.
     * 
     */
    public String id() {
        return this.id;
    }
    public Boolean isLockOverride() {
        return this.isLockOverride;
    }
    /**
     * @return Locks associated with this resource.
     * 
     */
    public List<GetStreamDistributionChannelsStreamDistributionChannelCollectionItemLock> locks() {
        return this.locks;
    }
    /**
     * @return A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time when the Stream Distribution Channel was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time when the Stream Distribution Channel was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStreamDistributionChannelsStreamDistributionChannelCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private String domainName;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isLockOverride;
        private List<GetStreamDistributionChannelsStreamDistributionChannelCollectionItemLock> locks;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetStreamDistributionChannelsStreamDistributionChannelCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.domainName = defaults.domainName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isLockOverride = defaults.isLockOverride;
    	      this.locks = defaults.locks;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder domainName(String domainName) {
            if (domainName == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "domainName");
            }
            this.domainName = domainName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isLockOverride(Boolean isLockOverride) {
            if (isLockOverride == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "isLockOverride");
            }
            this.isLockOverride = isLockOverride;
            return this;
        }
        @CustomType.Setter
        public Builder locks(List<GetStreamDistributionChannelsStreamDistributionChannelCollectionItemLock> locks) {
            if (locks == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "locks");
            }
            this.locks = locks;
            return this;
        }
        public Builder locks(GetStreamDistributionChannelsStreamDistributionChannelCollectionItemLock... locks) {
            return locks(List.of(locks));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetStreamDistributionChannelsStreamDistributionChannelCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetStreamDistributionChannelsStreamDistributionChannelCollectionItem build() {
            final var _resultValue = new GetStreamDistributionChannelsStreamDistributionChannelCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.domainName = domainName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isLockOverride = isLockOverride;
            _resultValue.locks = locks;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
