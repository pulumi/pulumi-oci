// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.DedicatedVmHostPlacementConstraintDetailsArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DedicatedVmHostArgs extends com.pulumi.resources.ResourceArgs {

    public static final DedicatedVmHostArgs Empty = new DedicatedVmHostArgs();

    /**
     * The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
     * 
     */
    @Import(name="dedicatedVmHostShape", required=true)
    private Output<String> dedicatedVmHostShape;

    /**
     * @return The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
     * 
     */
    public Output<String> dedicatedVmHostShape() {
        return this.dedicatedVmHostShape;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The fault domain for the dedicated virtual machine host&#39;s assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
     * 
     * To get a list of fault domains, use the `ListFaultDomains` operation in the [Identity and Access Management Service API](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/).
     * 
     * Example: `FAULT-DOMAIN-1`
     * 
     */
    @Import(name="faultDomain")
    private @Nullable Output<String> faultDomain;

    /**
     * @return The fault domain for the dedicated virtual machine host&#39;s assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
     * 
     * To get a list of fault domains, use the `ListFaultDomains` operation in the [Identity and Access Management Service API](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/).
     * 
     * Example: `FAULT-DOMAIN-1`
     * 
     */
    public Optional<Output<String>> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Generic placement details field which is overloaded with bare metal host id or host group id based on the resource we are targeting to launch.
     * 
     */
    @Import(name="placementConstraintDetails")
    private @Nullable Output<DedicatedVmHostPlacementConstraintDetailsArgs> placementConstraintDetails;

    /**
     * @return Generic placement details field which is overloaded with bare metal host id or host group id based on the resource we are targeting to launch.
     * 
     */
    public Optional<Output<DedicatedVmHostPlacementConstraintDetailsArgs>> placementConstraintDetails() {
        return Optional.ofNullable(this.placementConstraintDetails);
    }

    private DedicatedVmHostArgs() {}

    private DedicatedVmHostArgs(DedicatedVmHostArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.dedicatedVmHostShape = $.dedicatedVmHostShape;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.faultDomain = $.faultDomain;
        this.freeformTags = $.freeformTags;
        this.placementConstraintDetails = $.placementConstraintDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DedicatedVmHostArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DedicatedVmHostArgs $;

        public Builder() {
            $ = new DedicatedVmHostArgs();
        }

        public Builder(DedicatedVmHostArgs defaults) {
            $ = new DedicatedVmHostArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dedicatedVmHostShape The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
         * 
         * @return builder
         * 
         */
        public Builder dedicatedVmHostShape(Output<String> dedicatedVmHostShape) {
            $.dedicatedVmHostShape = dedicatedVmHostShape;
            return this;
        }

        /**
         * @param dedicatedVmHostShape The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
         * 
         * @return builder
         * 
         */
        public Builder dedicatedVmHostShape(String dedicatedVmHostShape) {
            return dedicatedVmHostShape(Output.of(dedicatedVmHostShape));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param faultDomain The fault domain for the dedicated virtual machine host&#39;s assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
         * 
         * To get a list of fault domains, use the `ListFaultDomains` operation in the [Identity and Access Management Service API](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/).
         * 
         * Example: `FAULT-DOMAIN-1`
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(@Nullable Output<String> faultDomain) {
            $.faultDomain = faultDomain;
            return this;
        }

        /**
         * @param faultDomain The fault domain for the dedicated virtual machine host&#39;s assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
         * 
         * To get a list of fault domains, use the `ListFaultDomains` operation in the [Identity and Access Management Service API](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/).
         * 
         * Example: `FAULT-DOMAIN-1`
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(String faultDomain) {
            return faultDomain(Output.of(faultDomain));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param placementConstraintDetails Generic placement details field which is overloaded with bare metal host id or host group id based on the resource we are targeting to launch.
         * 
         * @return builder
         * 
         */
        public Builder placementConstraintDetails(@Nullable Output<DedicatedVmHostPlacementConstraintDetailsArgs> placementConstraintDetails) {
            $.placementConstraintDetails = placementConstraintDetails;
            return this;
        }

        /**
         * @param placementConstraintDetails Generic placement details field which is overloaded with bare metal host id or host group id based on the resource we are targeting to launch.
         * 
         * @return builder
         * 
         */
        public Builder placementConstraintDetails(DedicatedVmHostPlacementConstraintDetailsArgs placementConstraintDetails) {
            return placementConstraintDetails(Output.of(placementConstraintDetails));
        }

        public DedicatedVmHostArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("DedicatedVmHostArgs", "availabilityDomain");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("DedicatedVmHostArgs", "compartmentId");
            }
            if ($.dedicatedVmHostShape == null) {
                throw new MissingRequiredPropertyException("DedicatedVmHostArgs", "dedicatedVmHostShape");
            }
            return $;
        }
    }

}
