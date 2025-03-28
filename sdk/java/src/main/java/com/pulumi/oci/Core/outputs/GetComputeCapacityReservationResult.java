// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetComputeCapacityReservationInstanceReservationConfig;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetComputeCapacityReservationResult {
    /**
     * @return The availability domain of the compute capacity reservation.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    private String capacityReservationId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the compute capacity reservation.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity reservation.
     * 
     */
    private String id;
    /**
     * @return The capacity configurations for the capacity reservation.
     * 
     */
    private List<GetComputeCapacityReservationInstanceReservationConfig> instanceReservationConfigs;
    /**
     * @return Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    private Boolean isDefaultReservation;
    /**
     * @return The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
     * 
     */
    private String reservedInstanceCount;
    /**
     * @return The current state of the compute capacity reservation.
     * 
     */
    private String state;
    /**
     * @return The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeUpdated;
    /**
     * @return The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
     * 
     */
    private String usedInstanceCount;

    private GetComputeCapacityReservationResult() {}
    /**
     * @return The availability domain of the compute capacity reservation.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    public String capacityReservationId() {
        return this.capacityReservationId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the compute capacity reservation.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
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
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity reservation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The capacity configurations for the capacity reservation.
     * 
     */
    public List<GetComputeCapacityReservationInstanceReservationConfig> instanceReservationConfigs() {
        return this.instanceReservationConfigs;
    }
    /**
     * @return Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    public Boolean isDefaultReservation() {
        return this.isDefaultReservation;
    }
    /**
     * @return The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
     * 
     */
    public String reservedInstanceCount() {
        return this.reservedInstanceCount;
    }
    /**
     * @return The current state of the compute capacity reservation.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
     * 
     */
    public String usedInstanceCount() {
        return this.usedInstanceCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeCapacityReservationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String capacityReservationId;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private List<GetComputeCapacityReservationInstanceReservationConfig> instanceReservationConfigs;
        private Boolean isDefaultReservation;
        private String reservedInstanceCount;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        private String usedInstanceCount;
        public Builder() {}
        public Builder(GetComputeCapacityReservationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.capacityReservationId = defaults.capacityReservationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.instanceReservationConfigs = defaults.instanceReservationConfigs;
    	      this.isDefaultReservation = defaults.isDefaultReservation;
    	      this.reservedInstanceCount = defaults.reservedInstanceCount;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.usedInstanceCount = defaults.usedInstanceCount;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder capacityReservationId(String capacityReservationId) {
            if (capacityReservationId == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "capacityReservationId");
            }
            this.capacityReservationId = capacityReservationId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceReservationConfigs(List<GetComputeCapacityReservationInstanceReservationConfig> instanceReservationConfigs) {
            if (instanceReservationConfigs == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "instanceReservationConfigs");
            }
            this.instanceReservationConfigs = instanceReservationConfigs;
            return this;
        }
        public Builder instanceReservationConfigs(GetComputeCapacityReservationInstanceReservationConfig... instanceReservationConfigs) {
            return instanceReservationConfigs(List.of(instanceReservationConfigs));
        }
        @CustomType.Setter
        public Builder isDefaultReservation(Boolean isDefaultReservation) {
            if (isDefaultReservation == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "isDefaultReservation");
            }
            this.isDefaultReservation = isDefaultReservation;
            return this;
        }
        @CustomType.Setter
        public Builder reservedInstanceCount(String reservedInstanceCount) {
            if (reservedInstanceCount == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "reservedInstanceCount");
            }
            this.reservedInstanceCount = reservedInstanceCount;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder usedInstanceCount(String usedInstanceCount) {
            if (usedInstanceCount == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationResult", "usedInstanceCount");
            }
            this.usedInstanceCount = usedInstanceCount;
            return this;
        }
        public GetComputeCapacityReservationResult build() {
            final var _resultValue = new GetComputeCapacityReservationResult();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.capacityReservationId = capacityReservationId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.instanceReservationConfigs = instanceReservationConfigs;
            _resultValue.isDefaultReservation = isDefaultReservation;
            _resultValue.reservedInstanceCount = reservedInstanceCount;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.usedInstanceCount = usedInstanceCount;
            return _resultValue;
        }
    }
}
