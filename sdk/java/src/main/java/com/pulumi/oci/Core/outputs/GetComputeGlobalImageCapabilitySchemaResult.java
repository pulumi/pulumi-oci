// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetComputeGlobalImageCapabilitySchemaResult {
    /**
     * @return The OCID of the compartment containing the compute global image capability schema
     * 
     */
    private String compartmentId;
    private String computeGlobalImageCapabilitySchemaId;
    /**
     * @return The name of the global capabilities version resource that is considered the current version.
     * 
     */
    private String currentVersionName;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The date and time the compute global image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetComputeGlobalImageCapabilitySchemaResult() {}
    /**
     * @return The OCID of the compartment containing the compute global image capability schema
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public String computeGlobalImageCapabilitySchemaId() {
        return this.computeGlobalImageCapabilitySchemaId;
    }
    /**
     * @return The name of the global capabilities version resource that is considered the current version.
     * 
     */
    public String currentVersionName() {
        return this.currentVersionName;
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
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The date and time the compute global image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeGlobalImageCapabilitySchemaResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String computeGlobalImageCapabilitySchemaId;
        private String currentVersionName;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String timeCreated;
        public Builder() {}
        public Builder(GetComputeGlobalImageCapabilitySchemaResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeGlobalImageCapabilitySchemaId = defaults.computeGlobalImageCapabilitySchemaId;
    	      this.currentVersionName = defaults.currentVersionName;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder computeGlobalImageCapabilitySchemaId(String computeGlobalImageCapabilitySchemaId) {
            this.computeGlobalImageCapabilitySchemaId = Objects.requireNonNull(computeGlobalImageCapabilitySchemaId);
            return this;
        }
        @CustomType.Setter
        public Builder currentVersionName(String currentVersionName) {
            this.currentVersionName = Objects.requireNonNull(currentVersionName);
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
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public GetComputeGlobalImageCapabilitySchemaResult build() {
            final var o = new GetComputeGlobalImageCapabilitySchemaResult();
            o.compartmentId = compartmentId;
            o.computeGlobalImageCapabilitySchemaId = computeGlobalImageCapabilitySchemaId;
            o.currentVersionName = currentVersionName;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}