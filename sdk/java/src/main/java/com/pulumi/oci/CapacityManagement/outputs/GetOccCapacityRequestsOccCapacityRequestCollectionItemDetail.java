// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailAssociatedOccHandoverResourceBlockList;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail {
    /**
     * @return The actual handed over quantity of resources at the time of request resolution.
     * 
     */
    private String actualHandoverQuantity;
    /**
     * @return A list containing details about occHandoverResourceBlocks which were handed over for the corresponding resource name.
     * 
     */
    private List<GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailAssociatedOccHandoverResourceBlockList> associatedOccHandoverResourceBlockLists;
    /**
     * @return The availability domain of the resource which is to be transferred. Note that this is only required for Capacity Request Transfer requests.
     * 
     */
    private String availabilityDomain;
    /**
     * @return The date on which the actual handover quantity of resources is delivered.
     * 
     */
    private String dateActualHandover;
    /**
     * @return The date on which the latest increment to supplied quantity of resources was delivered.
     * 
     */
    private String dateExpectedHandover;
    /**
     * @return The number of compute server&#39;s with name &lt;resourceName&gt; required by the user.
     * 
     */
    private String demandQuantity;
    /**
     * @return The incremental quantity of resources supplied as the provisioning is underway.
     * 
     */
    private String expectedHandoverQuantity;
    /**
     * @return The name of the COMPUTE server shape for which the request is made. Do not use CAPACITY_CONSTRAINT as the resource name.
     * 
     */
    private String resourceName;
    /**
     * @return The type of the resource against which the user wants to place a capacity request.
     * 
     */
    private String resourceType;
    /**
     * @return The WorkloadType from where capacity request are to be transferred.
     * 
     */
    private String sourceWorkloadType;
    /**
     * @return The type of the workload (Generic/ROW).
     * 
     */
    private String workloadType;

    private GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail() {}
    /**
     * @return The actual handed over quantity of resources at the time of request resolution.
     * 
     */
    public String actualHandoverQuantity() {
        return this.actualHandoverQuantity;
    }
    /**
     * @return A list containing details about occHandoverResourceBlocks which were handed over for the corresponding resource name.
     * 
     */
    public List<GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailAssociatedOccHandoverResourceBlockList> associatedOccHandoverResourceBlockLists() {
        return this.associatedOccHandoverResourceBlockLists;
    }
    /**
     * @return The availability domain of the resource which is to be transferred. Note that this is only required for Capacity Request Transfer requests.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The date on which the actual handover quantity of resources is delivered.
     * 
     */
    public String dateActualHandover() {
        return this.dateActualHandover;
    }
    /**
     * @return The date on which the latest increment to supplied quantity of resources was delivered.
     * 
     */
    public String dateExpectedHandover() {
        return this.dateExpectedHandover;
    }
    /**
     * @return The number of compute server&#39;s with name &lt;resourceName&gt; required by the user.
     * 
     */
    public String demandQuantity() {
        return this.demandQuantity;
    }
    /**
     * @return The incremental quantity of resources supplied as the provisioning is underway.
     * 
     */
    public String expectedHandoverQuantity() {
        return this.expectedHandoverQuantity;
    }
    /**
     * @return The name of the COMPUTE server shape for which the request is made. Do not use CAPACITY_CONSTRAINT as the resource name.
     * 
     */
    public String resourceName() {
        return this.resourceName;
    }
    /**
     * @return The type of the resource against which the user wants to place a capacity request.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return The WorkloadType from where capacity request are to be transferred.
     * 
     */
    public String sourceWorkloadType() {
        return this.sourceWorkloadType;
    }
    /**
     * @return The type of the workload (Generic/ROW).
     * 
     */
    public String workloadType() {
        return this.workloadType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String actualHandoverQuantity;
        private List<GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailAssociatedOccHandoverResourceBlockList> associatedOccHandoverResourceBlockLists;
        private String availabilityDomain;
        private String dateActualHandover;
        private String dateExpectedHandover;
        private String demandQuantity;
        private String expectedHandoverQuantity;
        private String resourceName;
        private String resourceType;
        private String sourceWorkloadType;
        private String workloadType;
        public Builder() {}
        public Builder(GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actualHandoverQuantity = defaults.actualHandoverQuantity;
    	      this.associatedOccHandoverResourceBlockLists = defaults.associatedOccHandoverResourceBlockLists;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.dateActualHandover = defaults.dateActualHandover;
    	      this.dateExpectedHandover = defaults.dateExpectedHandover;
    	      this.demandQuantity = defaults.demandQuantity;
    	      this.expectedHandoverQuantity = defaults.expectedHandoverQuantity;
    	      this.resourceName = defaults.resourceName;
    	      this.resourceType = defaults.resourceType;
    	      this.sourceWorkloadType = defaults.sourceWorkloadType;
    	      this.workloadType = defaults.workloadType;
        }

        @CustomType.Setter
        public Builder actualHandoverQuantity(String actualHandoverQuantity) {
            if (actualHandoverQuantity == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "actualHandoverQuantity");
            }
            this.actualHandoverQuantity = actualHandoverQuantity;
            return this;
        }
        @CustomType.Setter
        public Builder associatedOccHandoverResourceBlockLists(List<GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailAssociatedOccHandoverResourceBlockList> associatedOccHandoverResourceBlockLists) {
            if (associatedOccHandoverResourceBlockLists == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "associatedOccHandoverResourceBlockLists");
            }
            this.associatedOccHandoverResourceBlockLists = associatedOccHandoverResourceBlockLists;
            return this;
        }
        public Builder associatedOccHandoverResourceBlockLists(GetOccCapacityRequestsOccCapacityRequestCollectionItemDetailAssociatedOccHandoverResourceBlockList... associatedOccHandoverResourceBlockLists) {
            return associatedOccHandoverResourceBlockLists(List.of(associatedOccHandoverResourceBlockLists));
        }
        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder dateActualHandover(String dateActualHandover) {
            if (dateActualHandover == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "dateActualHandover");
            }
            this.dateActualHandover = dateActualHandover;
            return this;
        }
        @CustomType.Setter
        public Builder dateExpectedHandover(String dateExpectedHandover) {
            if (dateExpectedHandover == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "dateExpectedHandover");
            }
            this.dateExpectedHandover = dateExpectedHandover;
            return this;
        }
        @CustomType.Setter
        public Builder demandQuantity(String demandQuantity) {
            if (demandQuantity == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "demandQuantity");
            }
            this.demandQuantity = demandQuantity;
            return this;
        }
        @CustomType.Setter
        public Builder expectedHandoverQuantity(String expectedHandoverQuantity) {
            if (expectedHandoverQuantity == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "expectedHandoverQuantity");
            }
            this.expectedHandoverQuantity = expectedHandoverQuantity;
            return this;
        }
        @CustomType.Setter
        public Builder resourceName(String resourceName) {
            if (resourceName == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "resourceName");
            }
            this.resourceName = resourceName;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            if (resourceType == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "resourceType");
            }
            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder sourceWorkloadType(String sourceWorkloadType) {
            if (sourceWorkloadType == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "sourceWorkloadType");
            }
            this.sourceWorkloadType = sourceWorkloadType;
            return this;
        }
        @CustomType.Setter
        public Builder workloadType(String workloadType) {
            if (workloadType == null) {
              throw new MissingRequiredPropertyException("GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail", "workloadType");
            }
            this.workloadType = workloadType;
            return this;
        }
        public GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail build() {
            final var _resultValue = new GetOccCapacityRequestsOccCapacityRequestCollectionItemDetail();
            _resultValue.actualHandoverQuantity = actualHandoverQuantity;
            _resultValue.associatedOccHandoverResourceBlockLists = associatedOccHandoverResourceBlockLists;
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.dateActualHandover = dateActualHandover;
            _resultValue.dateExpectedHandover = dateExpectedHandover;
            _resultValue.demandQuantity = demandQuantity;
            _resultValue.expectedHandoverQuantity = expectedHandoverQuantity;
            _resultValue.resourceName = resourceName;
            _resultValue.resourceType = resourceType;
            _resultValue.sourceWorkloadType = sourceWorkloadType;
            _resultValue.workloadType = workloadType;
            return _resultValue;
        }
    }
}
