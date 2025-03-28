// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceMesh.inputs.VirtualDeploymentAccessLoggingArgs;
import com.pulumi.oci.ServiceMesh.inputs.VirtualDeploymentListenerArgs;
import com.pulumi.oci.ServiceMesh.inputs.VirtualDeploymentServiceDiscoveryArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VirtualDeploymentArgs extends com.pulumi.resources.ResourceArgs {

    public static final VirtualDeploymentArgs Empty = new VirtualDeploymentArgs();

    /**
     * (Updatable) This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    @Import(name="accessLogging")
    private @Nullable Output<VirtualDeploymentAccessLoggingArgs> accessLogging;

    /**
     * @return (Updatable) This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    public Optional<Output<VirtualDeploymentAccessLoggingArgs>> accessLogging() {
        return Optional.ofNullable(this.accessLogging);
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
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The listeners for the virtual deployment.
     * 
     */
    @Import(name="listeners")
    private @Nullable Output<List<VirtualDeploymentListenerArgs>> listeners;

    /**
     * @return (Updatable) The listeners for the virtual deployment.
     * 
     */
    public Optional<Output<List<VirtualDeploymentListenerArgs>>> listeners() {
        return Optional.ofNullable(this.listeners);
    }

    /**
     * A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) Service Discovery configuration for virtual deployments.
     * 
     */
    @Import(name="serviceDiscovery")
    private @Nullable Output<VirtualDeploymentServiceDiscoveryArgs> serviceDiscovery;

    /**
     * @return (Updatable) Service Discovery configuration for virtual deployments.
     * 
     */
    public Optional<Output<VirtualDeploymentServiceDiscoveryArgs>> serviceDiscovery() {
        return Optional.ofNullable(this.serviceDiscovery);
    }

    /**
     * The OCID of the service mesh in which this access policy is created.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="virtualServiceId", required=true)
    private Output<String> virtualServiceId;

    /**
     * @return The OCID of the service mesh in which this access policy is created.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> virtualServiceId() {
        return this.virtualServiceId;
    }

    private VirtualDeploymentArgs() {}

    private VirtualDeploymentArgs(VirtualDeploymentArgs $) {
        this.accessLogging = $.accessLogging;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.freeformTags = $.freeformTags;
        this.listeners = $.listeners;
        this.name = $.name;
        this.serviceDiscovery = $.serviceDiscovery;
        this.virtualServiceId = $.virtualServiceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VirtualDeploymentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VirtualDeploymentArgs $;

        public Builder() {
            $ = new VirtualDeploymentArgs();
        }

        public Builder(VirtualDeploymentArgs defaults) {
            $ = new VirtualDeploymentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessLogging (Updatable) This configuration determines if logging is enabled and where the logs will be output.
         * 
         * @return builder
         * 
         */
        public Builder accessLogging(@Nullable Output<VirtualDeploymentAccessLoggingArgs> accessLogging) {
            $.accessLogging = accessLogging;
            return this;
        }

        /**
         * @param accessLogging (Updatable) This configuration determines if logging is enabled and where the logs will be output.
         * 
         * @return builder
         * 
         */
        public Builder accessLogging(VirtualDeploymentAccessLoggingArgs accessLogging) {
            return accessLogging(Output.of(accessLogging));
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
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param listeners (Updatable) The listeners for the virtual deployment.
         * 
         * @return builder
         * 
         */
        public Builder listeners(@Nullable Output<List<VirtualDeploymentListenerArgs>> listeners) {
            $.listeners = listeners;
            return this;
        }

        /**
         * @param listeners (Updatable) The listeners for the virtual deployment.
         * 
         * @return builder
         * 
         */
        public Builder listeners(List<VirtualDeploymentListenerArgs> listeners) {
            return listeners(Output.of(listeners));
        }

        /**
         * @param listeners (Updatable) The listeners for the virtual deployment.
         * 
         * @return builder
         * 
         */
        public Builder listeners(VirtualDeploymentListenerArgs... listeners) {
            return listeners(List.of(listeners));
        }

        /**
         * @param name A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param serviceDiscovery (Updatable) Service Discovery configuration for virtual deployments.
         * 
         * @return builder
         * 
         */
        public Builder serviceDiscovery(@Nullable Output<VirtualDeploymentServiceDiscoveryArgs> serviceDiscovery) {
            $.serviceDiscovery = serviceDiscovery;
            return this;
        }

        /**
         * @param serviceDiscovery (Updatable) Service Discovery configuration for virtual deployments.
         * 
         * @return builder
         * 
         */
        public Builder serviceDiscovery(VirtualDeploymentServiceDiscoveryArgs serviceDiscovery) {
            return serviceDiscovery(Output.of(serviceDiscovery));
        }

        /**
         * @param virtualServiceId The OCID of the service mesh in which this access policy is created.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder virtualServiceId(Output<String> virtualServiceId) {
            $.virtualServiceId = virtualServiceId;
            return this;
        }

        /**
         * @param virtualServiceId The OCID of the service mesh in which this access policy is created.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder virtualServiceId(String virtualServiceId) {
            return virtualServiceId(Output.of(virtualServiceId));
        }

        public VirtualDeploymentArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("VirtualDeploymentArgs", "compartmentId");
            }
            if ($.virtualServiceId == null) {
                throw new MissingRequiredPropertyException("VirtualDeploymentArgs", "virtualServiceId");
            }
            return $;
        }
    }

}
