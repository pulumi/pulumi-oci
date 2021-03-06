// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
     * 
     */
    private final String computeGlobalImageCapabilitySchemaId;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private final String displayName;
    /**
     * @return The name of the compute global image capability schema version
     * 
     */
    private final String name;
    /**
     * @return The map of each capability name to its ImageCapabilityDescriptor.
     * 
     */
    private final Map<String,Object> schemaData;
    /**
     * @return The date and time the compute global image capability schema version was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;

    @CustomType.Constructor
    private GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion(
        @CustomType.Parameter("computeGlobalImageCapabilitySchemaId") String computeGlobalImageCapabilitySchemaId,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("schemaData") Map<String,Object> schemaData,
        @CustomType.Parameter("timeCreated") String timeCreated) {
        this.computeGlobalImageCapabilitySchemaId = computeGlobalImageCapabilitySchemaId;
        this.displayName = displayName;
        this.name = name;
        this.schemaData = schemaData;
        this.timeCreated = timeCreated;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
     * 
     */
    public String computeGlobalImageCapabilitySchemaId() {
        return this.computeGlobalImageCapabilitySchemaId;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The name of the compute global image capability schema version
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The map of each capability name to its ImageCapabilityDescriptor.
     * 
     */
    public Map<String,Object> schemaData() {
        return this.schemaData;
    }
    /**
     * @return The date and time the compute global image capability schema version was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String computeGlobalImageCapabilitySchemaId;
        private String displayName;
        private String name;
        private Map<String,Object> schemaData;
        private String timeCreated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.computeGlobalImageCapabilitySchemaId = defaults.computeGlobalImageCapabilitySchemaId;
    	      this.displayName = defaults.displayName;
    	      this.name = defaults.name;
    	      this.schemaData = defaults.schemaData;
    	      this.timeCreated = defaults.timeCreated;
        }

        public Builder computeGlobalImageCapabilitySchemaId(String computeGlobalImageCapabilitySchemaId) {
            this.computeGlobalImageCapabilitySchemaId = Objects.requireNonNull(computeGlobalImageCapabilitySchemaId);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder schemaData(Map<String,Object> schemaData) {
            this.schemaData = Objects.requireNonNull(schemaData);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }        public GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion build() {
            return new GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion(computeGlobalImageCapabilitySchemaId, displayName, name, schemaData, timeCreated);
        }
    }
}
