// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetComplianceRecordsComplianceRecordCollectionItemResource {
    /**
     * @return Compartment the resource belongs to.
     * 
     */
    private String compartment;
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Resource identifier.
     * 
     */
    private String resourceId;
    /**
     * @return Name of the resource.
     * 
     */
    private String resourceName;
    /**
     * @return Region the resource belongs to.
     * 
     */
    private String resourceRegion;

    private GetComplianceRecordsComplianceRecordCollectionItemResource() {}
    /**
     * @return Compartment the resource belongs to.
     * 
     */
    public String compartment() {
        return this.compartment;
    }
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Resource identifier.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return Name of the resource.
     * 
     */
    public String resourceName() {
        return this.resourceName;
    }
    /**
     * @return Region the resource belongs to.
     * 
     */
    public String resourceRegion() {
        return this.resourceRegion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComplianceRecordsComplianceRecordCollectionItemResource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartment;
        private String compartmentId;
        private String resourceId;
        private String resourceName;
        private String resourceRegion;
        public Builder() {}
        public Builder(GetComplianceRecordsComplianceRecordCollectionItemResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartment = defaults.compartment;
    	      this.compartmentId = defaults.compartmentId;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceName = defaults.resourceName;
    	      this.resourceRegion = defaults.resourceRegion;
        }

        @CustomType.Setter
        public Builder compartment(String compartment) {
            if (compartment == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsComplianceRecordCollectionItemResource", "compartment");
            }
            this.compartment = compartment;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsComplianceRecordCollectionItemResource", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            if (resourceId == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsComplianceRecordCollectionItemResource", "resourceId");
            }
            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceName(String resourceName) {
            if (resourceName == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsComplianceRecordCollectionItemResource", "resourceName");
            }
            this.resourceName = resourceName;
            return this;
        }
        @CustomType.Setter
        public Builder resourceRegion(String resourceRegion) {
            if (resourceRegion == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsComplianceRecordCollectionItemResource", "resourceRegion");
            }
            this.resourceRegion = resourceRegion;
            return this;
        }
        public GetComplianceRecordsComplianceRecordCollectionItemResource build() {
            final var _resultValue = new GetComplianceRecordsComplianceRecordCollectionItemResource();
            _resultValue.compartment = compartment;
            _resultValue.compartmentId = compartmentId;
            _resultValue.resourceId = resourceId;
            _resultValue.resourceName = resourceName;
            _resultValue.resourceRegion = resourceRegion;
            return _resultValue;
        }
    }
}
