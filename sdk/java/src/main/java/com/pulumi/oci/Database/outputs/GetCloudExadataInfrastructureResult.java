// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetCloudExadataInfrastructureCustomerContact;
import com.pulumi.oci.Database.outputs.GetCloudExadataInfrastructureMaintenanceWindow;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetCloudExadataInfrastructureResult {
    /**
     * @return The name of the availability domain that the cloud Exadata infrastructure resource is located in.
     * 
     */
    private String availabilityDomain;
    /**
     * @return The available storage can be allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
     * 
     */
    private Integer availableStorageSizeInGbs;
    private String cloudExadataInfrastructureId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The number of compute servers for the cloud Exadata infrastructure.
     * 
     */
    private Integer computeCount;
    /**
     * @return The list of customer email addresses that receive information from Oracle about the specified Oracle Cloud Infrastructure Database service resource. Oracle uses these email addresses to send notifications about planned and unplanned software maintenance updates, information about system hardware, and other information needed by administrators. Up to 10 email addresses can be added to the customer contacts for a cloud Exadata infrastructure instance.
     * 
     */
    private List<GetCloudExadataInfrastructureCustomerContact> customerContacts;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
     * 
     */
    private String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     * 
     */
    private String lastMaintenanceRunId;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    private List<GetCloudExadataInfrastructureMaintenanceWindow> maintenanceWindows;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     * 
     */
    private String nextMaintenanceRunId;
    /**
     * @return The model name of the cloud Exadata infrastructure resource.
     * 
     */
    private String shape;
    /**
     * @return The current lifecycle state of the cloud Exadata infrastructure resource.
     * 
     */
    private String state;
    /**
     * @return The number of storage servers for the cloud Exadata infrastructure.
     * 
     */
    private Integer storageCount;
    /**
     * @return The date and time the cloud Exadata infrastructure resource was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The total storage allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
     * 
     */
    private Integer totalStorageSizeInGbs;

    private GetCloudExadataInfrastructureResult() {}
    /**
     * @return The name of the availability domain that the cloud Exadata infrastructure resource is located in.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The available storage can be allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
     * 
     */
    public Integer availableStorageSizeInGbs() {
        return this.availableStorageSizeInGbs;
    }
    public String cloudExadataInfrastructureId() {
        return this.cloudExadataInfrastructureId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The number of compute servers for the cloud Exadata infrastructure.
     * 
     */
    public Integer computeCount() {
        return this.computeCount;
    }
    /**
     * @return The list of customer email addresses that receive information from Oracle about the specified Oracle Cloud Infrastructure Database service resource. Oracle uses these email addresses to send notifications about planned and unplanned software maintenance updates, information about system hardware, and other information needed by administrators. Up to 10 email addresses can be added to the customer contacts for a cloud Exadata infrastructure instance.
     * 
     */
    public List<GetCloudExadataInfrastructureCustomerContact> customerContacts() {
        return this.customerContacts;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     * 
     */
    public String lastMaintenanceRunId() {
        return this.lastMaintenanceRunId;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    public List<GetCloudExadataInfrastructureMaintenanceWindow> maintenanceWindows() {
        return this.maintenanceWindows;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     * 
     */
    public String nextMaintenanceRunId() {
        return this.nextMaintenanceRunId;
    }
    /**
     * @return The model name of the cloud Exadata infrastructure resource.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The current lifecycle state of the cloud Exadata infrastructure resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The number of storage servers for the cloud Exadata infrastructure.
     * 
     */
    public Integer storageCount() {
        return this.storageCount;
    }
    /**
     * @return The date and time the cloud Exadata infrastructure resource was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The total storage allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
     * 
     */
    public Integer totalStorageSizeInGbs() {
        return this.totalStorageSizeInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCloudExadataInfrastructureResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private Integer availableStorageSizeInGbs;
        private String cloudExadataInfrastructureId;
        private String compartmentId;
        private Integer computeCount;
        private List<GetCloudExadataInfrastructureCustomerContact> customerContacts;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String lastMaintenanceRunId;
        private String lifecycleDetails;
        private List<GetCloudExadataInfrastructureMaintenanceWindow> maintenanceWindows;
        private String nextMaintenanceRunId;
        private String shape;
        private String state;
        private Integer storageCount;
        private String timeCreated;
        private Integer totalStorageSizeInGbs;
        public Builder() {}
        public Builder(GetCloudExadataInfrastructureResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.availableStorageSizeInGbs = defaults.availableStorageSizeInGbs;
    	      this.cloudExadataInfrastructureId = defaults.cloudExadataInfrastructureId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeCount = defaults.computeCount;
    	      this.customerContacts = defaults.customerContacts;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lastMaintenanceRunId = defaults.lastMaintenanceRunId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.maintenanceWindows = defaults.maintenanceWindows;
    	      this.nextMaintenanceRunId = defaults.nextMaintenanceRunId;
    	      this.shape = defaults.shape;
    	      this.state = defaults.state;
    	      this.storageCount = defaults.storageCount;
    	      this.timeCreated = defaults.timeCreated;
    	      this.totalStorageSizeInGbs = defaults.totalStorageSizeInGbs;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder availableStorageSizeInGbs(Integer availableStorageSizeInGbs) {
            this.availableStorageSizeInGbs = Objects.requireNonNull(availableStorageSizeInGbs);
            return this;
        }
        @CustomType.Setter
        public Builder cloudExadataInfrastructureId(String cloudExadataInfrastructureId) {
            this.cloudExadataInfrastructureId = Objects.requireNonNull(cloudExadataInfrastructureId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder computeCount(Integer computeCount) {
            this.computeCount = Objects.requireNonNull(computeCount);
            return this;
        }
        @CustomType.Setter
        public Builder customerContacts(List<GetCloudExadataInfrastructureCustomerContact> customerContacts) {
            this.customerContacts = Objects.requireNonNull(customerContacts);
            return this;
        }
        public Builder customerContacts(GetCloudExadataInfrastructureCustomerContact... customerContacts) {
            return customerContacts(List.of(customerContacts));
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
        public Builder lastMaintenanceRunId(String lastMaintenanceRunId) {
            this.lastMaintenanceRunId = Objects.requireNonNull(lastMaintenanceRunId);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder maintenanceWindows(List<GetCloudExadataInfrastructureMaintenanceWindow> maintenanceWindows) {
            this.maintenanceWindows = Objects.requireNonNull(maintenanceWindows);
            return this;
        }
        public Builder maintenanceWindows(GetCloudExadataInfrastructureMaintenanceWindow... maintenanceWindows) {
            return maintenanceWindows(List.of(maintenanceWindows));
        }
        @CustomType.Setter
        public Builder nextMaintenanceRunId(String nextMaintenanceRunId) {
            this.nextMaintenanceRunId = Objects.requireNonNull(nextMaintenanceRunId);
            return this;
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder storageCount(Integer storageCount) {
            this.storageCount = Objects.requireNonNull(storageCount);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder totalStorageSizeInGbs(Integer totalStorageSizeInGbs) {
            this.totalStorageSizeInGbs = Objects.requireNonNull(totalStorageSizeInGbs);
            return this;
        }
        public GetCloudExadataInfrastructureResult build() {
            final var o = new GetCloudExadataInfrastructureResult();
            o.availabilityDomain = availabilityDomain;
            o.availableStorageSizeInGbs = availableStorageSizeInGbs;
            o.cloudExadataInfrastructureId = cloudExadataInfrastructureId;
            o.compartmentId = compartmentId;
            o.computeCount = computeCount;
            o.customerContacts = customerContacts;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lastMaintenanceRunId = lastMaintenanceRunId;
            o.lifecycleDetails = lifecycleDetails;
            o.maintenanceWindows = maintenanceWindows;
            o.nextMaintenanceRunId = nextMaintenanceRunId;
            o.shape = shape;
            o.state = state;
            o.storageCount = storageCount;
            o.timeCreated = timeCreated;
            o.totalStorageSizeInGbs = totalStorageSizeInGbs;
            return o;
        }
    }
}