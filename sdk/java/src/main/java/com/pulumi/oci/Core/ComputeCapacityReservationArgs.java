// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.ComputeCapacityReservationInstanceReservationConfigArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeCapacityReservationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeCapacityReservationArgs Empty = new ComputeCapacityReservationArgs();

    /**
     * The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain", required=true)
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
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
     * (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instance_reservation_configs field in oci.Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
     * 
     * To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
     * 
     */
    @Import(name="instanceReservationConfigs", required=true)
    private Output<List<ComputeCapacityReservationInstanceReservationConfigArgs>> instanceReservationConfigs;

    /**
     * @return (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instance_reservation_configs field in oci.Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
     * 
     * To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
     * 
     */
    public Output<List<ComputeCapacityReservationInstanceReservationConfigArgs>> instanceReservationConfigs() {
        return this.instanceReservationConfigs;
    }

    /**
     * (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="isDefaultReservation")
    private @Nullable Output<Boolean> isDefaultReservation;

    /**
     * @return (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Boolean>> isDefaultReservation() {
        return Optional.ofNullable(this.isDefaultReservation);
    }

    private ComputeCapacityReservationArgs() {}

    private ComputeCapacityReservationArgs(ComputeCapacityReservationArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.instanceReservationConfigs = $.instanceReservationConfigs;
        this.isDefaultReservation = $.isDefaultReservation;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeCapacityReservationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeCapacityReservationArgs $;

        public Builder() {
            $ = new ComputeCapacityReservationArgs();
        }

        public Builder(ComputeCapacityReservationArgs defaults) {
            $ = new ComputeCapacityReservationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
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
         * @param instanceReservationConfigs (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instance_reservation_configs field in oci.Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
         * 
         * To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
         * 
         * @return builder
         * 
         */
        public Builder instanceReservationConfigs(Output<List<ComputeCapacityReservationInstanceReservationConfigArgs>> instanceReservationConfigs) {
            $.instanceReservationConfigs = instanceReservationConfigs;
            return this;
        }

        /**
         * @param instanceReservationConfigs (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instance_reservation_configs field in oci.Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
         * 
         * To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
         * 
         * @return builder
         * 
         */
        public Builder instanceReservationConfigs(List<ComputeCapacityReservationInstanceReservationConfigArgs> instanceReservationConfigs) {
            return instanceReservationConfigs(Output.of(instanceReservationConfigs));
        }

        /**
         * @param instanceReservationConfigs (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instance_reservation_configs field in oci.Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
         * 
         * To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
         * 
         * @return builder
         * 
         */
        public Builder instanceReservationConfigs(ComputeCapacityReservationInstanceReservationConfigArgs... instanceReservationConfigs) {
            return instanceReservationConfigs(List.of(instanceReservationConfigs));
        }

        /**
         * @param isDefaultReservation (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder isDefaultReservation(@Nullable Output<Boolean> isDefaultReservation) {
            $.isDefaultReservation = isDefaultReservation;
            return this;
        }

        /**
         * @param isDefaultReservation (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder isDefaultReservation(Boolean isDefaultReservation) {
            return isDefaultReservation(Output.of(isDefaultReservation));
        }

        public ComputeCapacityReservationArgs build() {
            if ($.availabilityDomain == null) {
                throw new MissingRequiredPropertyException("ComputeCapacityReservationArgs", "availabilityDomain");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ComputeCapacityReservationArgs", "compartmentId");
            }
            if ($.instanceReservationConfigs == null) {
                throw new MissingRequiredPropertyException("ComputeCapacityReservationArgs", "instanceReservationConfigs");
            }
            return $;
        }
    }

}
