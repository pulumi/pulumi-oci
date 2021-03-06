// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.CloudExadataInfrastructureCustomerContactArgs;
import com.pulumi.oci.Database.inputs.CloudExadataInfrastructureMaintenanceWindowArgs;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CloudExadataInfrastructureArgs extends com.pulumi.resources.ResourceArgs {

    public static final CloudExadataInfrastructureArgs Empty = new CloudExadataInfrastructureArgs();

    /**
     * The availability domain where the cloud Exadata infrastructure is located.
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain where the cloud Exadata infrastructure is located.
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) The number of compute servers for the cloud Exadata infrastructure.
     * 
     */
    @Import(name="computeCount")
    private @Nullable Output<Integer> computeCount;

    /**
     * @return (Updatable) The number of compute servers for the cloud Exadata infrastructure.
     * 
     */
    public Optional<Output<Integer>> computeCount() {
        return Optional.ofNullable(this.computeCount);
    }

    /**
     * (Updatable) Customer contacts.
     * 
     */
    @Import(name="customerContacts")
    private @Nullable Output<List<CloudExadataInfrastructureCustomerContactArgs>> customerContacts;

    /**
     * @return (Updatable) Customer contacts.
     * 
     */
    public Optional<Output<List<CloudExadataInfrastructureCustomerContactArgs>>> customerContacts() {
        return Optional.ofNullable(this.customerContacts);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    @Import(name="maintenanceWindow")
    private @Nullable Output<CloudExadataInfrastructureMaintenanceWindowArgs> maintenanceWindow;

    /**
     * @return (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    public Optional<Output<CloudExadataInfrastructureMaintenanceWindowArgs>> maintenanceWindow() {
        return Optional.ofNullable(this.maintenanceWindow);
    }

    /**
     * The shape of the cloud Exadata infrastructure resource.
     * 
     */
    @Import(name="shape", required=true)
    private Output<String> shape;

    /**
     * @return The shape of the cloud Exadata infrastructure resource.
     * 
     */
    public Output<String> shape() {
        return this.shape;
    }

    /**
     * (Updatable) The number of storage servers for the cloud Exadata infrastructure.
     * 
     */
    @Import(name="storageCount")
    private @Nullable Output<Integer> storageCount;

    /**
     * @return (Updatable) The number of storage servers for the cloud Exadata infrastructure.
     * 
     */
    public Optional<Output<Integer>> storageCount() {
        return Optional.ofNullable(this.storageCount);
    }

    private CloudExadataInfrastructureArgs() {}

    private CloudExadataInfrastructureArgs(CloudExadataInfrastructureArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.computeCount = $.computeCount;
        this.customerContacts = $.customerContacts;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.maintenanceWindow = $.maintenanceWindow;
        this.shape = $.shape;
        this.storageCount = $.storageCount;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CloudExadataInfrastructureArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CloudExadataInfrastructureArgs $;

        public Builder() {
            $ = new CloudExadataInfrastructureArgs();
        }

        public Builder(CloudExadataInfrastructureArgs defaults) {
            $ = new CloudExadataInfrastructureArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The availability domain where the cloud Exadata infrastructure is located.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain where the cloud Exadata infrastructure is located.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param computeCount (Updatable) The number of compute servers for the cloud Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder computeCount(@Nullable Output<Integer> computeCount) {
            $.computeCount = computeCount;
            return this;
        }

        /**
         * @param computeCount (Updatable) The number of compute servers for the cloud Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder computeCount(Integer computeCount) {
            return computeCount(Output.of(computeCount));
        }

        /**
         * @param customerContacts (Updatable) Customer contacts.
         * 
         * @return builder
         * 
         */
        public Builder customerContacts(@Nullable Output<List<CloudExadataInfrastructureCustomerContactArgs>> customerContacts) {
            $.customerContacts = customerContacts;
            return this;
        }

        /**
         * @param customerContacts (Updatable) Customer contacts.
         * 
         * @return builder
         * 
         */
        public Builder customerContacts(List<CloudExadataInfrastructureCustomerContactArgs> customerContacts) {
            return customerContacts(Output.of(customerContacts));
        }

        /**
         * @param customerContacts (Updatable) Customer contacts.
         * 
         * @return builder
         * 
         */
        public Builder customerContacts(CloudExadataInfrastructureCustomerContactArgs... customerContacts) {
            return customerContacts(List.of(customerContacts));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param maintenanceWindow (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
         * 
         * @return builder
         * 
         */
        public Builder maintenanceWindow(@Nullable Output<CloudExadataInfrastructureMaintenanceWindowArgs> maintenanceWindow) {
            $.maintenanceWindow = maintenanceWindow;
            return this;
        }

        /**
         * @param maintenanceWindow (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
         * 
         * @return builder
         * 
         */
        public Builder maintenanceWindow(CloudExadataInfrastructureMaintenanceWindowArgs maintenanceWindow) {
            return maintenanceWindow(Output.of(maintenanceWindow));
        }

        /**
         * @param shape The shape of the cloud Exadata infrastructure resource.
         * 
         * @return builder
         * 
         */
        public Builder shape(Output<String> shape) {
            $.shape = shape;
            return this;
        }

        /**
         * @param shape The shape of the cloud Exadata infrastructure resource.
         * 
         * @return builder
         * 
         */
        public Builder shape(String shape) {
            return shape(Output.of(shape));
        }

        /**
         * @param storageCount (Updatable) The number of storage servers for the cloud Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder storageCount(@Nullable Output<Integer> storageCount) {
            $.storageCount = storageCount;
            return this;
        }

        /**
         * @param storageCount (Updatable) The number of storage servers for the cloud Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder storageCount(Integer storageCount) {
            return storageCount(Output.of(storageCount));
        }

        public CloudExadataInfrastructureArgs build() {
            $.availabilityDomain = Objects.requireNonNull($.availabilityDomain, "expected parameter 'availabilityDomain' to be non-null");
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.shape = Objects.requireNonNull($.shape, "expected parameter 'shape' to be non-null");
            return $;
        }
    }

}
