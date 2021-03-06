// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetail;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationResult {
    /**
     * @return The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    private final String compartmentId;
    /**
     * @return Parameters that were not specified when the instance configuration was created, but that are required to launch an instance from the instance configuration. See the [LaunchInstanceConfiguration](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance/LaunchInstanceConfiguration) operation.
     * 
     */
    private final List<String> deferredFields;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID of the volume backup.
     * 
     */
    private final String id;
    private final String instanceConfigurationId;
    private final List<GetInstanceConfigurationInstanceDetail> instanceDetails;
    private final String instanceId;
    private final String source;
    /**
     * @return The date and time the instance configuration was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;

    @CustomType.Constructor
    private GetInstanceConfigurationResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("deferredFields") List<String> deferredFields,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("instanceConfigurationId") String instanceConfigurationId,
        @CustomType.Parameter("instanceDetails") List<GetInstanceConfigurationInstanceDetail> instanceDetails,
        @CustomType.Parameter("instanceId") String instanceId,
        @CustomType.Parameter("source") String source,
        @CustomType.Parameter("timeCreated") String timeCreated) {
        this.compartmentId = compartmentId;
        this.deferredFields = deferredFields;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.instanceConfigurationId = instanceConfigurationId;
        this.instanceDetails = instanceDetails;
        this.instanceId = instanceId;
        this.source = source;
        this.timeCreated = timeCreated;
    }

    /**
     * @return The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Parameters that were not specified when the instance configuration was created, but that are required to launch an instance from the instance configuration. See the [LaunchInstanceConfiguration](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance/LaunchInstanceConfiguration) operation.
     * 
     */
    public List<String> deferredFields() {
        return this.deferredFields;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the volume backup.
     * 
     */
    public String id() {
        return this.id;
    }
    public String instanceConfigurationId() {
        return this.instanceConfigurationId;
    }
    public List<GetInstanceConfigurationInstanceDetail> instanceDetails() {
        return this.instanceDetails;
    }
    public String instanceId() {
        return this.instanceId;
    }
    public String source() {
        return this.source;
    }
    /**
     * @return The date and time the instance configuration was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private List<String> deferredFields;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String instanceConfigurationId;
        private List<GetInstanceConfigurationInstanceDetail> instanceDetails;
        private String instanceId;
        private String source;
        private String timeCreated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstanceConfigurationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.deferredFields = defaults.deferredFields;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.instanceConfigurationId = defaults.instanceConfigurationId;
    	      this.instanceDetails = defaults.instanceDetails;
    	      this.instanceId = defaults.instanceId;
    	      this.source = defaults.source;
    	      this.timeCreated = defaults.timeCreated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder deferredFields(List<String> deferredFields) {
            this.deferredFields = Objects.requireNonNull(deferredFields);
            return this;
        }
        public Builder deferredFields(String... deferredFields) {
            return deferredFields(List.of(deferredFields));
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder instanceConfigurationId(String instanceConfigurationId) {
            this.instanceConfigurationId = Objects.requireNonNull(instanceConfigurationId);
            return this;
        }
        public Builder instanceDetails(List<GetInstanceConfigurationInstanceDetail> instanceDetails) {
            this.instanceDetails = Objects.requireNonNull(instanceDetails);
            return this;
        }
        public Builder instanceDetails(GetInstanceConfigurationInstanceDetail... instanceDetails) {
            return instanceDetails(List.of(instanceDetails));
        }
        public Builder instanceId(String instanceId) {
            this.instanceId = Objects.requireNonNull(instanceId);
            return this;
        }
        public Builder source(String source) {
            this.source = Objects.requireNonNull(source);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }        public GetInstanceConfigurationResult build() {
            return new GetInstanceConfigurationResult(compartmentId, deferredFields, definedTags, displayName, freeformTags, id, instanceConfigurationId, instanceDetails, instanceId, source, timeCreated);
        }
    }
}
