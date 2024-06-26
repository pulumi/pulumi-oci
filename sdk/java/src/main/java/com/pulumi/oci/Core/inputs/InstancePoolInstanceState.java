// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.InstancePoolInstanceLoadBalancerBackendArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstancePoolInstanceState extends com.pulumi.resources.ResourceArgs {

    public static final InstancePoolInstanceState Empty = new InstancePoolInstanceState();

    @Import(name="autoTerminateInstanceOnDelete")
    private @Nullable Output<Boolean> autoTerminateInstanceOnDelete;

    public Optional<Output<Boolean>> autoTerminateInstanceOnDelete() {
        return Optional.ofNullable(this.autoTerminateInstanceOnDelete);
    }

    /**
     * The availability domain the instance is running in.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return The availability domain the instance is running in.
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="decrementSizeOnDelete")
    private @Nullable Output<Boolean> decrementSizeOnDelete;

    public Optional<Output<Boolean>> decrementSizeOnDelete() {
        return Optional.ofNullable(this.decrementSizeOnDelete);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The fault domain the instance is running in.
     * 
     */
    @Import(name="faultDomain")
    private @Nullable Output<String> faultDomain;

    /**
     * @return The fault domain the instance is running in.
     * 
     */
    public Optional<Output<String>> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
     * 
     */
    @Import(name="instanceConfigurationId")
    private @Nullable Output<String> instanceConfigurationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
     * 
     */
    public Optional<Output<String>> instanceConfigurationId() {
        return Optional.ofNullable(this.instanceConfigurationId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    @Import(name="instanceId")
    private @Nullable Output<String> instanceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    public Optional<Output<String>> instanceId() {
        return Optional.ofNullable(this.instanceId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="instancePoolId")
    private @Nullable Output<String> instancePoolId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> instancePoolId() {
        return Optional.ofNullable(this.instancePoolId);
    }

    /**
     * The load balancer backends that are configured for the instance pool instance.
     * 
     */
    @Import(name="loadBalancerBackends")
    private @Nullable Output<List<InstancePoolInstanceLoadBalancerBackendArgs>> loadBalancerBackends;

    /**
     * @return The load balancer backends that are configured for the instance pool instance.
     * 
     */
    public Optional<Output<List<InstancePoolInstanceLoadBalancerBackendArgs>>> loadBalancerBackends() {
        return Optional.ofNullable(this.loadBalancerBackends);
    }

    /**
     * The region that contains the availability domain the instance is running in.
     * 
     */
    @Import(name="region")
    private @Nullable Output<String> region;

    /**
     * @return The region that contains the availability domain the instance is running in.
     * 
     */
    public Optional<Output<String>> region() {
        return Optional.ofNullable(this.region);
    }

    /**
     * The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    @Import(name="shape")
    private @Nullable Output<String> shape;

    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    public Optional<Output<String>> shape() {
        return Optional.ofNullable(this.shape);
    }

    /**
     * The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private InstancePoolInstanceState() {}

    private InstancePoolInstanceState(InstancePoolInstanceState $) {
        this.autoTerminateInstanceOnDelete = $.autoTerminateInstanceOnDelete;
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.decrementSizeOnDelete = $.decrementSizeOnDelete;
        this.displayName = $.displayName;
        this.faultDomain = $.faultDomain;
        this.instanceConfigurationId = $.instanceConfigurationId;
        this.instanceId = $.instanceId;
        this.instancePoolId = $.instancePoolId;
        this.loadBalancerBackends = $.loadBalancerBackends;
        this.region = $.region;
        this.shape = $.shape;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstancePoolInstanceState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstancePoolInstanceState $;

        public Builder() {
            $ = new InstancePoolInstanceState();
        }

        public Builder(InstancePoolInstanceState defaults) {
            $ = new InstancePoolInstanceState(Objects.requireNonNull(defaults));
        }

        public Builder autoTerminateInstanceOnDelete(@Nullable Output<Boolean> autoTerminateInstanceOnDelete) {
            $.autoTerminateInstanceOnDelete = autoTerminateInstanceOnDelete;
            return this;
        }

        public Builder autoTerminateInstanceOnDelete(Boolean autoTerminateInstanceOnDelete) {
            return autoTerminateInstanceOnDelete(Output.of(autoTerminateInstanceOnDelete));
        }

        /**
         * @param availabilityDomain The availability domain the instance is running in.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The availability domain the instance is running in.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder decrementSizeOnDelete(@Nullable Output<Boolean> decrementSizeOnDelete) {
            $.decrementSizeOnDelete = decrementSizeOnDelete;
            return this;
        }

        public Builder decrementSizeOnDelete(Boolean decrementSizeOnDelete) {
            return decrementSizeOnDelete(Output.of(decrementSizeOnDelete));
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param faultDomain The fault domain the instance is running in.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(@Nullable Output<String> faultDomain) {
            $.faultDomain = faultDomain;
            return this;
        }

        /**
         * @param faultDomain The fault domain the instance is running in.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(String faultDomain) {
            return faultDomain(Output.of(faultDomain));
        }

        /**
         * @param instanceConfigurationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceConfigurationId(@Nullable Output<String> instanceConfigurationId) {
            $.instanceConfigurationId = instanceConfigurationId;
            return this;
        }

        /**
         * @param instanceConfigurationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceConfigurationId(String instanceConfigurationId) {
            return instanceConfigurationId(Output.of(instanceConfigurationId));
        }

        /**
         * @param instanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(@Nullable Output<String> instanceId) {
            $.instanceId = instanceId;
            return this;
        }

        /**
         * @param instanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(String instanceId) {
            return instanceId(Output.of(instanceId));
        }

        /**
         * @param instancePoolId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder instancePoolId(@Nullable Output<String> instancePoolId) {
            $.instancePoolId = instancePoolId;
            return this;
        }

        /**
         * @param instancePoolId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder instancePoolId(String instancePoolId) {
            return instancePoolId(Output.of(instancePoolId));
        }

        /**
         * @param loadBalancerBackends The load balancer backends that are configured for the instance pool instance.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerBackends(@Nullable Output<List<InstancePoolInstanceLoadBalancerBackendArgs>> loadBalancerBackends) {
            $.loadBalancerBackends = loadBalancerBackends;
            return this;
        }

        /**
         * @param loadBalancerBackends The load balancer backends that are configured for the instance pool instance.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerBackends(List<InstancePoolInstanceLoadBalancerBackendArgs> loadBalancerBackends) {
            return loadBalancerBackends(Output.of(loadBalancerBackends));
        }

        /**
         * @param loadBalancerBackends The load balancer backends that are configured for the instance pool instance.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerBackends(InstancePoolInstanceLoadBalancerBackendArgs... loadBalancerBackends) {
            return loadBalancerBackends(List.of(loadBalancerBackends));
        }

        /**
         * @param region The region that contains the availability domain the instance is running in.
         * 
         * @return builder
         * 
         */
        public Builder region(@Nullable Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region The region that contains the availability domain the instance is running in.
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        /**
         * @param shape The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
         * 
         * @return builder
         * 
         */
        public Builder shape(@Nullable Output<String> shape) {
            $.shape = shape;
            return this;
        }

        /**
         * @param shape The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
         * 
         * @return builder
         * 
         */
        public Builder shape(String shape) {
            return shape(Output.of(shape));
        }

        /**
         * @param state The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public InstancePoolInstanceState build() {
            return $;
        }
    }

}
