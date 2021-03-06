// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstancePoolInstancesInstanceLoadBalancerBackend;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstancePoolInstancesInstance {
    private final Boolean autoTerminateInstanceOnDelete;
    /**
     * @return The availability domain the instance is running in.
     * 
     */
    private final String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final String compartmentId;
    private final Boolean decrementSizeOnDelete;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private final String displayName;
    /**
     * @return The fault domain the instance is running in.
     * 
     */
    private final String faultDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    private final String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
     * 
     */
    private final String instanceConfigurationId;
    private final String instanceId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     */
    private final String instancePoolId;
    /**
     * @return The load balancer backends that are configured for the instance pool instance.
     * 
     */
    private final List<GetInstancePoolInstancesInstanceLoadBalancerBackend> loadBalancerBackends;
    /**
     * @return The region that contains the availability domain the instance is running in.
     * 
     */
    private final String region;
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    private final String shape;
    /**
     * @return The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    private final String state;
    /**
     * @return The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;

    @CustomType.Constructor
    private GetInstancePoolInstancesInstance(
        @CustomType.Parameter("autoTerminateInstanceOnDelete") Boolean autoTerminateInstanceOnDelete,
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("decrementSizeOnDelete") Boolean decrementSizeOnDelete,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("faultDomain") String faultDomain,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("instanceConfigurationId") String instanceConfigurationId,
        @CustomType.Parameter("instanceId") String instanceId,
        @CustomType.Parameter("instancePoolId") String instancePoolId,
        @CustomType.Parameter("loadBalancerBackends") List<GetInstancePoolInstancesInstanceLoadBalancerBackend> loadBalancerBackends,
        @CustomType.Parameter("region") String region,
        @CustomType.Parameter("shape") String shape,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated) {
        this.autoTerminateInstanceOnDelete = autoTerminateInstanceOnDelete;
        this.availabilityDomain = availabilityDomain;
        this.compartmentId = compartmentId;
        this.decrementSizeOnDelete = decrementSizeOnDelete;
        this.displayName = displayName;
        this.faultDomain = faultDomain;
        this.id = id;
        this.instanceConfigurationId = instanceConfigurationId;
        this.instanceId = instanceId;
        this.instancePoolId = instancePoolId;
        this.loadBalancerBackends = loadBalancerBackends;
        this.region = region;
        this.shape = shape;
        this.state = state;
        this.timeCreated = timeCreated;
    }

    public Boolean autoTerminateInstanceOnDelete() {
        return this.autoTerminateInstanceOnDelete;
    }
    /**
     * @return The availability domain the instance is running in.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Boolean decrementSizeOnDelete() {
        return this.decrementSizeOnDelete;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The fault domain the instance is running in.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
     * 
     */
    public String instanceConfigurationId() {
        return this.instanceConfigurationId;
    }
    public String instanceId() {
        return this.instanceId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     */
    public String instancePoolId() {
        return this.instancePoolId;
    }
    /**
     * @return The load balancer backends that are configured for the instance pool instance.
     * 
     */
    public List<GetInstancePoolInstancesInstanceLoadBalancerBackend> loadBalancerBackends() {
        return this.loadBalancerBackends;
    }
    /**
     * @return The region that contains the availability domain the instance is running in.
     * 
     */
    public String region() {
        return this.region;
    }
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstancePoolInstancesInstance defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean autoTerminateInstanceOnDelete;
        private String availabilityDomain;
        private String compartmentId;
        private Boolean decrementSizeOnDelete;
        private String displayName;
        private String faultDomain;
        private String id;
        private String instanceConfigurationId;
        private String instanceId;
        private String instancePoolId;
        private List<GetInstancePoolInstancesInstanceLoadBalancerBackend> loadBalancerBackends;
        private String region;
        private String shape;
        private String state;
        private String timeCreated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstancePoolInstancesInstance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autoTerminateInstanceOnDelete = defaults.autoTerminateInstanceOnDelete;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.decrementSizeOnDelete = defaults.decrementSizeOnDelete;
    	      this.displayName = defaults.displayName;
    	      this.faultDomain = defaults.faultDomain;
    	      this.id = defaults.id;
    	      this.instanceConfigurationId = defaults.instanceConfigurationId;
    	      this.instanceId = defaults.instanceId;
    	      this.instancePoolId = defaults.instancePoolId;
    	      this.loadBalancerBackends = defaults.loadBalancerBackends;
    	      this.region = defaults.region;
    	      this.shape = defaults.shape;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        public Builder autoTerminateInstanceOnDelete(Boolean autoTerminateInstanceOnDelete) {
            this.autoTerminateInstanceOnDelete = Objects.requireNonNull(autoTerminateInstanceOnDelete);
            return this;
        }
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder decrementSizeOnDelete(Boolean decrementSizeOnDelete) {
            this.decrementSizeOnDelete = Objects.requireNonNull(decrementSizeOnDelete);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder faultDomain(String faultDomain) {
            this.faultDomain = Objects.requireNonNull(faultDomain);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder instanceConfigurationId(String instanceConfigurationId) {
            this.instanceConfigurationId = Objects.requireNonNull(instanceConfigurationId);
            return this;
        }
        public Builder instanceId(String instanceId) {
            this.instanceId = Objects.requireNonNull(instanceId);
            return this;
        }
        public Builder instancePoolId(String instancePoolId) {
            this.instancePoolId = Objects.requireNonNull(instancePoolId);
            return this;
        }
        public Builder loadBalancerBackends(List<GetInstancePoolInstancesInstanceLoadBalancerBackend> loadBalancerBackends) {
            this.loadBalancerBackends = Objects.requireNonNull(loadBalancerBackends);
            return this;
        }
        public Builder loadBalancerBackends(GetInstancePoolInstancesInstanceLoadBalancerBackend... loadBalancerBackends) {
            return loadBalancerBackends(List.of(loadBalancerBackends));
        }
        public Builder region(String region) {
            this.region = Objects.requireNonNull(region);
            return this;
        }
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }        public GetInstancePoolInstancesInstance build() {
            return new GetInstancePoolInstancesInstance(autoTerminateInstanceOnDelete, availabilityDomain, compartmentId, decrementSizeOnDelete, displayName, faultDomain, id, instanceConfigurationId, instanceId, instancePoolId, loadBalancerBackends, region, shape, state, timeCreated);
        }
    }
}
