// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerInstances.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstanceContainer;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstanceDnsConfig;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstanceImagePullSecret;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstanceShapeConfig;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstanceVnic;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstanceVolume;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetContainerInstanceResult {
    /**
     * @return Availability Domain where the ContainerInstance is running.
     * 
     */
    private String availabilityDomain;
    /**
     * @return Compartment Identifier
     * 
     */
    private String compartmentId;
    /**
     * @return The number of containers on this Instance
     * 
     */
    private Integer containerCount;
    private String containerInstanceId;
    /**
     * @return The container restart policy is applied for all containers in container instance.
     * 
     */
    private String containerRestartPolicy;
    /**
     * @return The Containers on this Instance
     * 
     */
    private List<GetContainerInstanceContainer> containers;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Display name for the ContainerInstance. Can be renamed.
     * 
     */
    private String displayName;
    /**
     * @return DNS settings for containers.
     * 
     */
    private List<GetContainerInstanceDnsConfig> dnsConfigs;
    /**
     * @return Fault Domain where the ContainerInstance is running.
     * 
     */
    private String faultDomain;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Duration in seconds processes within a Container have to gracefully terminate. This applies whenever a Container must be halted, such as when the Container Instance is deleted. Processes will first be sent a termination signal. After this timeout is reached, the processes will be sent a termination signal.
     * 
     */
    private String gracefulShutdownTimeoutInSeconds;
    /**
     * @return Unique identifier that is immutable on creation
     * 
     */
    private String id;
    /**
     * @return The image pull secrets for accessing private registry to pull images for containers
     * 
     */
    private List<GetContainerInstanceImagePullSecret> imagePullSecrets;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The shape of the Container Instance. The shape determines the resources available to the Container Instance.
     * 
     */
    private String shape;
    /**
     * @return The shape configuration for a Container Instance. The shape configuration determines the resources allocated to the Instance and it&#39;s containers.
     * 
     */
    private List<GetContainerInstanceShapeConfig> shapeConfigs;
    /**
     * @return The current state of the ContainerInstance.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the the ContainerInstance was created. An RFC3339 formatted datetime string
     * 
     */
    private String timeCreated;
    /**
     * @return The time the ContainerInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    private String timeUpdated;
    /**
     * @return The virtual networks available to containers running on this Container Instance.
     * 
     */
    private List<GetContainerInstanceVnic> vnics;
    /**
     * @return The number of volumes that attached to this Instance
     * 
     */
    private Integer volumeCount;
    /**
     * @return A Volume represents a directory with data that is accessible across multiple containers in a ContainerInstance.
     * 
     */
    private List<GetContainerInstanceVolume> volumes;

    private GetContainerInstanceResult() {}
    /**
     * @return Availability Domain where the ContainerInstance is running.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return Compartment Identifier
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The number of containers on this Instance
     * 
     */
    public Integer containerCount() {
        return this.containerCount;
    }
    public String containerInstanceId() {
        return this.containerInstanceId;
    }
    /**
     * @return The container restart policy is applied for all containers in container instance.
     * 
     */
    public String containerRestartPolicy() {
        return this.containerRestartPolicy;
    }
    /**
     * @return The Containers on this Instance
     * 
     */
    public List<GetContainerInstanceContainer> containers() {
        return this.containers;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Display name for the ContainerInstance. Can be renamed.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return DNS settings for containers.
     * 
     */
    public List<GetContainerInstanceDnsConfig> dnsConfigs() {
        return this.dnsConfigs;
    }
    /**
     * @return Fault Domain where the ContainerInstance is running.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Duration in seconds processes within a Container have to gracefully terminate. This applies whenever a Container must be halted, such as when the Container Instance is deleted. Processes will first be sent a termination signal. After this timeout is reached, the processes will be sent a termination signal.
     * 
     */
    public String gracefulShutdownTimeoutInSeconds() {
        return this.gracefulShutdownTimeoutInSeconds;
    }
    /**
     * @return Unique identifier that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The image pull secrets for accessing private registry to pull images for containers
     * 
     */
    public List<GetContainerInstanceImagePullSecret> imagePullSecrets() {
        return this.imagePullSecrets;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The shape of the Container Instance. The shape determines the resources available to the Container Instance.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The shape configuration for a Container Instance. The shape configuration determines the resources allocated to the Instance and it&#39;s containers.
     * 
     */
    public List<GetContainerInstanceShapeConfig> shapeConfigs() {
        return this.shapeConfigs;
    }
    /**
     * @return The current state of the ContainerInstance.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the the ContainerInstance was created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the ContainerInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The virtual networks available to containers running on this Container Instance.
     * 
     */
    public List<GetContainerInstanceVnic> vnics() {
        return this.vnics;
    }
    /**
     * @return The number of volumes that attached to this Instance
     * 
     */
    public Integer volumeCount() {
        return this.volumeCount;
    }
    /**
     * @return A Volume represents a directory with data that is accessible across multiple containers in a ContainerInstance.
     * 
     */
    public List<GetContainerInstanceVolume> volumes() {
        return this.volumes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerInstanceResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private Integer containerCount;
        private String containerInstanceId;
        private String containerRestartPolicy;
        private List<GetContainerInstanceContainer> containers;
        private Map<String,Object> definedTags;
        private String displayName;
        private List<GetContainerInstanceDnsConfig> dnsConfigs;
        private String faultDomain;
        private Map<String,Object> freeformTags;
        private String gracefulShutdownTimeoutInSeconds;
        private String id;
        private List<GetContainerInstanceImagePullSecret> imagePullSecrets;
        private String lifecycleDetails;
        private String shape;
        private List<GetContainerInstanceShapeConfig> shapeConfigs;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private List<GetContainerInstanceVnic> vnics;
        private Integer volumeCount;
        private List<GetContainerInstanceVolume> volumes;
        public Builder() {}
        public Builder(GetContainerInstanceResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.containerCount = defaults.containerCount;
    	      this.containerInstanceId = defaults.containerInstanceId;
    	      this.containerRestartPolicy = defaults.containerRestartPolicy;
    	      this.containers = defaults.containers;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.dnsConfigs = defaults.dnsConfigs;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.gracefulShutdownTimeoutInSeconds = defaults.gracefulShutdownTimeoutInSeconds;
    	      this.id = defaults.id;
    	      this.imagePullSecrets = defaults.imagePullSecrets;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.shape = defaults.shape;
    	      this.shapeConfigs = defaults.shapeConfigs;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.vnics = defaults.vnics;
    	      this.volumeCount = defaults.volumeCount;
    	      this.volumes = defaults.volumes;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder containerCount(Integer containerCount) {
            this.containerCount = Objects.requireNonNull(containerCount);
            return this;
        }
        @CustomType.Setter
        public Builder containerInstanceId(String containerInstanceId) {
            this.containerInstanceId = Objects.requireNonNull(containerInstanceId);
            return this;
        }
        @CustomType.Setter
        public Builder containerRestartPolicy(String containerRestartPolicy) {
            this.containerRestartPolicy = Objects.requireNonNull(containerRestartPolicy);
            return this;
        }
        @CustomType.Setter
        public Builder containers(List<GetContainerInstanceContainer> containers) {
            this.containers = Objects.requireNonNull(containers);
            return this;
        }
        public Builder containers(GetContainerInstanceContainer... containers) {
            return containers(List.of(containers));
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
        public Builder dnsConfigs(List<GetContainerInstanceDnsConfig> dnsConfigs) {
            this.dnsConfigs = Objects.requireNonNull(dnsConfigs);
            return this;
        }
        public Builder dnsConfigs(GetContainerInstanceDnsConfig... dnsConfigs) {
            return dnsConfigs(List.of(dnsConfigs));
        }
        @CustomType.Setter
        public Builder faultDomain(String faultDomain) {
            this.faultDomain = Objects.requireNonNull(faultDomain);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder gracefulShutdownTimeoutInSeconds(String gracefulShutdownTimeoutInSeconds) {
            this.gracefulShutdownTimeoutInSeconds = Objects.requireNonNull(gracefulShutdownTimeoutInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder imagePullSecrets(List<GetContainerInstanceImagePullSecret> imagePullSecrets) {
            this.imagePullSecrets = Objects.requireNonNull(imagePullSecrets);
            return this;
        }
        public Builder imagePullSecrets(GetContainerInstanceImagePullSecret... imagePullSecrets) {
            return imagePullSecrets(List.of(imagePullSecrets));
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        @CustomType.Setter
        public Builder shapeConfigs(List<GetContainerInstanceShapeConfig> shapeConfigs) {
            this.shapeConfigs = Objects.requireNonNull(shapeConfigs);
            return this;
        }
        public Builder shapeConfigs(GetContainerInstanceShapeConfig... shapeConfigs) {
            return shapeConfigs(List.of(shapeConfigs));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder vnics(List<GetContainerInstanceVnic> vnics) {
            this.vnics = Objects.requireNonNull(vnics);
            return this;
        }
        public Builder vnics(GetContainerInstanceVnic... vnics) {
            return vnics(List.of(vnics));
        }
        @CustomType.Setter
        public Builder volumeCount(Integer volumeCount) {
            this.volumeCount = Objects.requireNonNull(volumeCount);
            return this;
        }
        @CustomType.Setter
        public Builder volumes(List<GetContainerInstanceVolume> volumes) {
            this.volumes = Objects.requireNonNull(volumes);
            return this;
        }
        public Builder volumes(GetContainerInstanceVolume... volumes) {
            return volumes(List.of(volumes));
        }
        public GetContainerInstanceResult build() {
            final var o = new GetContainerInstanceResult();
            o.availabilityDomain = availabilityDomain;
            o.compartmentId = compartmentId;
            o.containerCount = containerCount;
            o.containerInstanceId = containerInstanceId;
            o.containerRestartPolicy = containerRestartPolicy;
            o.containers = containers;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.dnsConfigs = dnsConfigs;
            o.faultDomain = faultDomain;
            o.freeformTags = freeformTags;
            o.gracefulShutdownTimeoutInSeconds = gracefulShutdownTimeoutInSeconds;
            o.id = id;
            o.imagePullSecrets = imagePullSecrets;
            o.lifecycleDetails = lifecycleDetails;
            o.shape = shape;
            o.shapeConfigs = shapeConfigs;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.vnics = vnics;
            o.volumeCount = volumeCount;
            o.volumes = volumes;
            return o;
        }
    }
}