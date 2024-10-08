// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetExternalDbNodeResult {
    /**
     * @return The additional details of the external DB node defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> additionalDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The name of the external DB node.
     * 
     */
    private String componentName;
    /**
     * @return The number of CPU cores available on the DB node.
     * 
     */
    private Double cpuCoreCount;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The user-friendly name for the external DB node. The name does not have to be unique.
     * 
     */
    private String displayName;
    /**
     * @return Name of the domain.
     * 
     */
    private String domainName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     * 
     */
    private String externalConnectorId;
    private String externalDbNodeId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the DB node is a part of.
     * 
     */
    private String externalDbSystemId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The host name for the DB node.
     * 
     */
    private String hostName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
     * 
     */
    private String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The total memory in gigabytes (GB) on the DB node.
     * 
     */
    private Double memorySizeInGbs;
    /**
     * @return The current lifecycle state of the external DB node.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time the external DB node was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the external DB node was last updated.
     * 
     */
    private String timeUpdated;

    private GetExternalDbNodeResult() {}
    /**
     * @return The additional details of the external DB node defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> additionalDetails() {
        return this.additionalDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The name of the external DB node.
     * 
     */
    public String componentName() {
        return this.componentName;
    }
    /**
     * @return The number of CPU cores available on the DB node.
     * 
     */
    public Double cpuCoreCount() {
        return this.cpuCoreCount;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The user-friendly name for the external DB node. The name does not have to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Name of the domain.
     * 
     */
    public String domainName() {
        return this.domainName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     * 
     */
    public String externalConnectorId() {
        return this.externalConnectorId;
    }
    public String externalDbNodeId() {
        return this.externalDbNodeId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the DB node is a part of.
     * 
     */
    public String externalDbSystemId() {
        return this.externalDbSystemId;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The host name for the DB node.
     * 
     */
    public String hostName() {
        return this.hostName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The total memory in gigabytes (GB) on the DB node.
     * 
     */
    public Double memorySizeInGbs() {
        return this.memorySizeInGbs;
    }
    /**
     * @return The current lifecycle state of the external DB node.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time the external DB node was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the external DB node was last updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbNodeResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,String> additionalDetails;
        private String compartmentId;
        private String componentName;
        private Double cpuCoreCount;
        private Map<String,String> definedTags;
        private String displayName;
        private String domainName;
        private String externalConnectorId;
        private String externalDbNodeId;
        private String externalDbSystemId;
        private Map<String,String> freeformTags;
        private String hostName;
        private String id;
        private String lifecycleDetails;
        private Double memorySizeInGbs;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetExternalDbNodeResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalDetails = defaults.additionalDetails;
    	      this.compartmentId = defaults.compartmentId;
    	      this.componentName = defaults.componentName;
    	      this.cpuCoreCount = defaults.cpuCoreCount;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.domainName = defaults.domainName;
    	      this.externalConnectorId = defaults.externalConnectorId;
    	      this.externalDbNodeId = defaults.externalDbNodeId;
    	      this.externalDbSystemId = defaults.externalDbSystemId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.hostName = defaults.hostName;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.memorySizeInGbs = defaults.memorySizeInGbs;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder additionalDetails(Map<String,String> additionalDetails) {
            if (additionalDetails == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "additionalDetails");
            }
            this.additionalDetails = additionalDetails;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder componentName(String componentName) {
            if (componentName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "componentName");
            }
            this.componentName = componentName;
            return this;
        }
        @CustomType.Setter
        public Builder cpuCoreCount(Double cpuCoreCount) {
            if (cpuCoreCount == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "cpuCoreCount");
            }
            this.cpuCoreCount = cpuCoreCount;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder domainName(String domainName) {
            if (domainName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "domainName");
            }
            this.domainName = domainName;
            return this;
        }
        @CustomType.Setter
        public Builder externalConnectorId(String externalConnectorId) {
            if (externalConnectorId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "externalConnectorId");
            }
            this.externalConnectorId = externalConnectorId;
            return this;
        }
        @CustomType.Setter
        public Builder externalDbNodeId(String externalDbNodeId) {
            if (externalDbNodeId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "externalDbNodeId");
            }
            this.externalDbNodeId = externalDbNodeId;
            return this;
        }
        @CustomType.Setter
        public Builder externalDbSystemId(String externalDbSystemId) {
            if (externalDbSystemId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "externalDbSystemId");
            }
            this.externalDbSystemId = externalDbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder hostName(String hostName) {
            if (hostName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "hostName");
            }
            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder memorySizeInGbs(Double memorySizeInGbs) {
            if (memorySizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "memorySizeInGbs");
            }
            this.memorySizeInGbs = memorySizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetExternalDbNodeResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetExternalDbNodeResult build() {
            final var _resultValue = new GetExternalDbNodeResult();
            _resultValue.additionalDetails = additionalDetails;
            _resultValue.compartmentId = compartmentId;
            _resultValue.componentName = componentName;
            _resultValue.cpuCoreCount = cpuCoreCount;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.domainName = domainName;
            _resultValue.externalConnectorId = externalConnectorId;
            _resultValue.externalDbNodeId = externalDbNodeId;
            _resultValue.externalDbSystemId = externalDbSystemId;
            _resultValue.freeformTags = freeformTags;
            _resultValue.hostName = hostName;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.memorySizeInGbs = memorySizeInGbs;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
