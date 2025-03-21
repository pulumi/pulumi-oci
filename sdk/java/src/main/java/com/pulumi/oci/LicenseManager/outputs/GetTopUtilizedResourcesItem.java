// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LicenseManager.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTopUtilizedResourcesItem {
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that contains the resource.
     * 
     */
    private String resourceCompartmentId;
    /**
     * @return The display name of the compartment that contains the resource.
     * 
     */
    private String resourceCompartmentName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private String resourceId;
    /**
     * @return Resource canonical name.
     * 
     */
    private String resourceName;
    /**
     * @return Number of license units consumed by the resource.
     * 
     */
    private Double totalUnits;
    /**
     * @return The resource unit.
     * 
     */
    private String unitType;

    private GetTopUtilizedResourcesItem() {}
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that contains the resource.
     * 
     */
    public String resourceCompartmentId() {
        return this.resourceCompartmentId;
    }
    /**
     * @return The display name of the compartment that contains the resource.
     * 
     */
    public String resourceCompartmentName() {
        return this.resourceCompartmentName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return Resource canonical name.
     * 
     */
    public String resourceName() {
        return this.resourceName;
    }
    /**
     * @return Number of license units consumed by the resource.
     * 
     */
    public Double totalUnits() {
        return this.totalUnits;
    }
    /**
     * @return The resource unit.
     * 
     */
    public String unitType() {
        return this.unitType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTopUtilizedResourcesItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String resourceCompartmentId;
        private String resourceCompartmentName;
        private String resourceId;
        private String resourceName;
        private Double totalUnits;
        private String unitType;
        public Builder() {}
        public Builder(GetTopUtilizedResourcesItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.resourceCompartmentId = defaults.resourceCompartmentId;
    	      this.resourceCompartmentName = defaults.resourceCompartmentName;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceName = defaults.resourceName;
    	      this.totalUnits = defaults.totalUnits;
    	      this.unitType = defaults.unitType;
        }

        @CustomType.Setter
        public Builder resourceCompartmentId(String resourceCompartmentId) {
            if (resourceCompartmentId == null) {
              throw new MissingRequiredPropertyException("GetTopUtilizedResourcesItem", "resourceCompartmentId");
            }
            this.resourceCompartmentId = resourceCompartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceCompartmentName(String resourceCompartmentName) {
            if (resourceCompartmentName == null) {
              throw new MissingRequiredPropertyException("GetTopUtilizedResourcesItem", "resourceCompartmentName");
            }
            this.resourceCompartmentName = resourceCompartmentName;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            if (resourceId == null) {
              throw new MissingRequiredPropertyException("GetTopUtilizedResourcesItem", "resourceId");
            }
            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceName(String resourceName) {
            if (resourceName == null) {
              throw new MissingRequiredPropertyException("GetTopUtilizedResourcesItem", "resourceName");
            }
            this.resourceName = resourceName;
            return this;
        }
        @CustomType.Setter
        public Builder totalUnits(Double totalUnits) {
            if (totalUnits == null) {
              throw new MissingRequiredPropertyException("GetTopUtilizedResourcesItem", "totalUnits");
            }
            this.totalUnits = totalUnits;
            return this;
        }
        @CustomType.Setter
        public Builder unitType(String unitType) {
            if (unitType == null) {
              throw new MissingRequiredPropertyException("GetTopUtilizedResourcesItem", "unitType");
            }
            this.unitType = unitType;
            return this;
        }
        public GetTopUtilizedResourcesItem build() {
            final var _resultValue = new GetTopUtilizedResourcesItem();
            _resultValue.resourceCompartmentId = resourceCompartmentId;
            _resultValue.resourceCompartmentName = resourceCompartmentName;
            _resultValue.resourceId = resourceId;
            _resultValue.resourceName = resourceName;
            _resultValue.totalUnits = totalUnits;
            _resultValue.unitType = unitType;
            return _resultValue;
        }
    }
}
