// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ContainerEngine.inputs.ContainerInstanceContainerHealthCheckArgs;
import com.pulumi.oci.ContainerEngine.inputs.ContainerInstanceContainerResourceConfigArgs;
import com.pulumi.oci.ContainerEngine.inputs.ContainerInstanceContainerVolumeMountArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ContainerInstanceContainerArgs extends com.pulumi.resources.ResourceArgs {

    public static final ContainerInstanceContainerArgs Empty = new ContainerInstanceContainerArgs();

    /**
     * A list of additional capabilities for the container.
     * 
     */
    @Import(name="additionalCapabilities")
    private @Nullable Output<List<String>> additionalCapabilities;

    /**
     * @return A list of additional capabilities for the container.
     * 
     */
    public Optional<Output<List<String>>> additionalCapabilities() {
        return Optional.ofNullable(this.additionalCapabilities);
    }

    /**
     * A list of string arguments for a container&#39;s entrypoint process.
     * 
     */
    @Import(name="arguments")
    private @Nullable Output<List<String>> arguments;

    /**
     * @return A list of string arguments for a container&#39;s entrypoint process.
     * 
     */
    public Optional<Output<List<String>>> arguments() {
        return Optional.ofNullable(this.arguments);
    }

    /**
     * Availability Domain where the ContainerInstance should be created.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return Availability Domain where the ContainerInstance should be created.
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The list of strings which will be concatenated to a single command for checking container&#39;s status.
     * 
     */
    @Import(name="commands")
    private @Nullable Output<List<String>> commands;

    /**
     * @return The list of strings which will be concatenated to a single command for checking container&#39;s status.
     * 
     */
    public Optional<Output<List<String>>> commands() {
        return Optional.ofNullable(this.commands);
    }

    /**
     * (Updatable) Compartment Identifier
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The ID of the Container on this Instance.
     * 
     */
    @Import(name="containerId")
    private @Nullable Output<String> containerId;

    /**
     * @return The ID of the Container on this Instance.
     * 
     */
    public Optional<Output<String>> containerId() {
        return Optional.ofNullable(this.containerId);
    }

    @Import(name="containerInstanceId")
    private @Nullable Output<String> containerInstanceId;

    public Optional<Output<String>> containerInstanceId() {
        return Optional.ofNullable(this.containerInstanceId);
    }

    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * A user-friendly name for the VNIC. Does not have to be unique. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name for the VNIC. Does not have to be unique. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * A map of additional environment variables to set in the environment of the container&#39;s entrypoint process. These variables are in addition to any variables already defined in the container&#39;s image.
     * 
     */
    @Import(name="environmentVariables")
    private @Nullable Output<Map<String,Object>> environmentVariables;

    /**
     * @return A map of additional environment variables to set in the environment of the container&#39;s entrypoint process. These variables are in addition to any variables already defined in the container&#39;s image.
     * 
     */
    public Optional<Output<Map<String,Object>>> environmentVariables() {
        return Optional.ofNullable(this.environmentVariables);
    }

    @Import(name="exitCode")
    private @Nullable Output<Integer> exitCode;

    public Optional<Output<Integer>> exitCode() {
        return Optional.ofNullable(this.exitCode);
    }

    /**
     * Fault Domain where the ContainerInstance should run.
     * 
     */
    @Import(name="faultDomain")
    private @Nullable Output<String> faultDomain;

    /**
     * @return Fault Domain where the ContainerInstance should run.
     * 
     */
    public Optional<Output<String>> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }

    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * list of container health checks to check container status and take appropriate action if container status is failed. There are three types of health checks that we currently support HTTP, TCP, and Command.
     * 
     */
    @Import(name="healthChecks")
    private @Nullable Output<List<ContainerInstanceContainerHealthCheckArgs>> healthChecks;

    /**
     * @return list of container health checks to check container status and take appropriate action if container status is failed. There are three types of health checks that we currently support HTTP, TCP, and Command.
     * 
     */
    public Optional<Output<List<ContainerInstanceContainerHealthCheckArgs>>> healthChecks() {
        return Optional.ofNullable(this.healthChecks);
    }

    /**
     * The container image information. Currently only support public docker registry. Can be either image name, e.g `containerImage`, image name with version, e.g `containerImage:v1` or complete docker image Url e.g `docker.io/library/containerImage:latest`. If no registry is provided, will default the registry to public docker hub `docker.io/library`. The registry used for container image must be reachable over the Container Instance&#39;s VNIC.
     * 
     */
    @Import(name="imageUrl", required=true)
    private Output<String> imageUrl;

    /**
     * @return The container image information. Currently only support public docker registry. Can be either image name, e.g `containerImage`, image name with version, e.g `containerImage:v1` or complete docker image Url e.g `docker.io/library/containerImage:latest`. If no registry is provided, will default the registry to public docker hub `docker.io/library`. The registry used for container image must be reachable over the Container Instance&#39;s VNIC.
     * 
     */
    public Output<String> imageUrl() {
        return this.imageUrl;
    }

    /**
     * Determines if the Container will have access to the Container Instance Resource Principal.  This method utilizes resource principal version 2.2. Please refer to  https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdk_authentication_methods.htm#sdk_authentication_methods_resource_principal  for detailed explanation of how to leverage the exposed resource principal elements.
     * 
     */
    @Import(name="isResourcePrincipalDisabled")
    private @Nullable Output<Boolean> isResourcePrincipalDisabled;

    /**
     * @return Determines if the Container will have access to the Container Instance Resource Principal.  This method utilizes resource principal version 2.2. Please refer to  https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdk_authentication_methods.htm#sdk_authentication_methods_resource_principal  for detailed explanation of how to leverage the exposed resource principal elements.
     * 
     */
    public Optional<Output<Boolean>> isResourcePrincipalDisabled() {
        return Optional.ofNullable(this.isResourcePrincipalDisabled);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The size and amount of resources available to the Container.
     * 
     */
    @Import(name="resourceConfig")
    private @Nullable Output<ContainerInstanceContainerResourceConfigArgs> resourceConfig;

    /**
     * @return The size and amount of resources available to the Container.
     * 
     */
    public Optional<Output<ContainerInstanceContainerResourceConfigArgs>> resourceConfig() {
        return Optional.ofNullable(this.resourceConfig);
    }

    /**
     * (Updatable) The target state for the Container Instance. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The target state for the Container Instance. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time the the ContainerInstance was created. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the the ContainerInstance was created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    @Import(name="timeTerminated")
    private @Nullable Output<String> timeTerminated;

    public Optional<Output<String>> timeTerminated() {
        return Optional.ofNullable(this.timeTerminated);
    }

    /**
     * The time the ContainerInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the ContainerInstance was updated. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * List of the volume mounts.
     * 
     */
    @Import(name="volumeMounts")
    private @Nullable Output<List<ContainerInstanceContainerVolumeMountArgs>> volumeMounts;

    /**
     * @return List of the volume mounts.
     * 
     */
    public Optional<Output<List<ContainerInstanceContainerVolumeMountArgs>>> volumeMounts() {
        return Optional.ofNullable(this.volumeMounts);
    }

    /**
     * The working directory within the Container&#39;s filesystem for the Container process. If none is set, the Container will run in the working directory set by the container image.
     * 
     */
    @Import(name="workingDirectory")
    private @Nullable Output<String> workingDirectory;

    /**
     * @return The working directory within the Container&#39;s filesystem for the Container process. If none is set, the Container will run in the working directory set by the container image.
     * 
     */
    public Optional<Output<String>> workingDirectory() {
        return Optional.ofNullable(this.workingDirectory);
    }

    private ContainerInstanceContainerArgs() {}

    private ContainerInstanceContainerArgs(ContainerInstanceContainerArgs $) {
        this.additionalCapabilities = $.additionalCapabilities;
        this.arguments = $.arguments;
        this.availabilityDomain = $.availabilityDomain;
        this.commands = $.commands;
        this.compartmentId = $.compartmentId;
        this.containerId = $.containerId;
        this.containerInstanceId = $.containerInstanceId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.environmentVariables = $.environmentVariables;
        this.exitCode = $.exitCode;
        this.faultDomain = $.faultDomain;
        this.freeformTags = $.freeformTags;
        this.healthChecks = $.healthChecks;
        this.imageUrl = $.imageUrl;
        this.isResourcePrincipalDisabled = $.isResourcePrincipalDisabled;
        this.lifecycleDetails = $.lifecycleDetails;
        this.resourceConfig = $.resourceConfig;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeTerminated = $.timeTerminated;
        this.timeUpdated = $.timeUpdated;
        this.volumeMounts = $.volumeMounts;
        this.workingDirectory = $.workingDirectory;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerInstanceContainerArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerInstanceContainerArgs $;

        public Builder() {
            $ = new ContainerInstanceContainerArgs();
        }

        public Builder(ContainerInstanceContainerArgs defaults) {
            $ = new ContainerInstanceContainerArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param additionalCapabilities A list of additional capabilities for the container.
         * 
         * @return builder
         * 
         */
        public Builder additionalCapabilities(@Nullable Output<List<String>> additionalCapabilities) {
            $.additionalCapabilities = additionalCapabilities;
            return this;
        }

        /**
         * @param additionalCapabilities A list of additional capabilities for the container.
         * 
         * @return builder
         * 
         */
        public Builder additionalCapabilities(List<String> additionalCapabilities) {
            return additionalCapabilities(Output.of(additionalCapabilities));
        }

        /**
         * @param additionalCapabilities A list of additional capabilities for the container.
         * 
         * @return builder
         * 
         */
        public Builder additionalCapabilities(String... additionalCapabilities) {
            return additionalCapabilities(List.of(additionalCapabilities));
        }

        /**
         * @param arguments A list of string arguments for a container&#39;s entrypoint process.
         * 
         * @return builder
         * 
         */
        public Builder arguments(@Nullable Output<List<String>> arguments) {
            $.arguments = arguments;
            return this;
        }

        /**
         * @param arguments A list of string arguments for a container&#39;s entrypoint process.
         * 
         * @return builder
         * 
         */
        public Builder arguments(List<String> arguments) {
            return arguments(Output.of(arguments));
        }

        /**
         * @param arguments A list of string arguments for a container&#39;s entrypoint process.
         * 
         * @return builder
         * 
         */
        public Builder arguments(String... arguments) {
            return arguments(List.of(arguments));
        }

        /**
         * @param availabilityDomain Availability Domain where the ContainerInstance should be created.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain Availability Domain where the ContainerInstance should be created.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param commands The list of strings which will be concatenated to a single command for checking container&#39;s status.
         * 
         * @return builder
         * 
         */
        public Builder commands(@Nullable Output<List<String>> commands) {
            $.commands = commands;
            return this;
        }

        /**
         * @param commands The list of strings which will be concatenated to a single command for checking container&#39;s status.
         * 
         * @return builder
         * 
         */
        public Builder commands(List<String> commands) {
            return commands(Output.of(commands));
        }

        /**
         * @param commands The list of strings which will be concatenated to a single command for checking container&#39;s status.
         * 
         * @return builder
         * 
         */
        public Builder commands(String... commands) {
            return commands(List.of(commands));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param containerId The ID of the Container on this Instance.
         * 
         * @return builder
         * 
         */
        public Builder containerId(@Nullable Output<String> containerId) {
            $.containerId = containerId;
            return this;
        }

        /**
         * @param containerId The ID of the Container on this Instance.
         * 
         * @return builder
         * 
         */
        public Builder containerId(String containerId) {
            return containerId(Output.of(containerId));
        }

        public Builder containerInstanceId(@Nullable Output<String> containerInstanceId) {
            $.containerInstanceId = containerInstanceId;
            return this;
        }

        public Builder containerInstanceId(String containerInstanceId) {
            return containerInstanceId(Output.of(containerInstanceId));
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName A user-friendly name for the VNIC. Does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name for the VNIC. Does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param environmentVariables A map of additional environment variables to set in the environment of the container&#39;s entrypoint process. These variables are in addition to any variables already defined in the container&#39;s image.
         * 
         * @return builder
         * 
         */
        public Builder environmentVariables(@Nullable Output<Map<String,Object>> environmentVariables) {
            $.environmentVariables = environmentVariables;
            return this;
        }

        /**
         * @param environmentVariables A map of additional environment variables to set in the environment of the container&#39;s entrypoint process. These variables are in addition to any variables already defined in the container&#39;s image.
         * 
         * @return builder
         * 
         */
        public Builder environmentVariables(Map<String,Object> environmentVariables) {
            return environmentVariables(Output.of(environmentVariables));
        }

        public Builder exitCode(@Nullable Output<Integer> exitCode) {
            $.exitCode = exitCode;
            return this;
        }

        public Builder exitCode(Integer exitCode) {
            return exitCode(Output.of(exitCode));
        }

        /**
         * @param faultDomain Fault Domain where the ContainerInstance should run.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(@Nullable Output<String> faultDomain) {
            $.faultDomain = faultDomain;
            return this;
        }

        /**
         * @param faultDomain Fault Domain where the ContainerInstance should run.
         * 
         * @return builder
         * 
         */
        public Builder faultDomain(String faultDomain) {
            return faultDomain(Output.of(faultDomain));
        }

        /**
         * @param freeformTags Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param healthChecks list of container health checks to check container status and take appropriate action if container status is failed. There are three types of health checks that we currently support HTTP, TCP, and Command.
         * 
         * @return builder
         * 
         */
        public Builder healthChecks(@Nullable Output<List<ContainerInstanceContainerHealthCheckArgs>> healthChecks) {
            $.healthChecks = healthChecks;
            return this;
        }

        /**
         * @param healthChecks list of container health checks to check container status and take appropriate action if container status is failed. There are three types of health checks that we currently support HTTP, TCP, and Command.
         * 
         * @return builder
         * 
         */
        public Builder healthChecks(List<ContainerInstanceContainerHealthCheckArgs> healthChecks) {
            return healthChecks(Output.of(healthChecks));
        }

        /**
         * @param healthChecks list of container health checks to check container status and take appropriate action if container status is failed. There are three types of health checks that we currently support HTTP, TCP, and Command.
         * 
         * @return builder
         * 
         */
        public Builder healthChecks(ContainerInstanceContainerHealthCheckArgs... healthChecks) {
            return healthChecks(List.of(healthChecks));
        }

        /**
         * @param imageUrl The container image information. Currently only support public docker registry. Can be either image name, e.g `containerImage`, image name with version, e.g `containerImage:v1` or complete docker image Url e.g `docker.io/library/containerImage:latest`. If no registry is provided, will default the registry to public docker hub `docker.io/library`. The registry used for container image must be reachable over the Container Instance&#39;s VNIC.
         * 
         * @return builder
         * 
         */
        public Builder imageUrl(Output<String> imageUrl) {
            $.imageUrl = imageUrl;
            return this;
        }

        /**
         * @param imageUrl The container image information. Currently only support public docker registry. Can be either image name, e.g `containerImage`, image name with version, e.g `containerImage:v1` or complete docker image Url e.g `docker.io/library/containerImage:latest`. If no registry is provided, will default the registry to public docker hub `docker.io/library`. The registry used for container image must be reachable over the Container Instance&#39;s VNIC.
         * 
         * @return builder
         * 
         */
        public Builder imageUrl(String imageUrl) {
            return imageUrl(Output.of(imageUrl));
        }

        /**
         * @param isResourcePrincipalDisabled Determines if the Container will have access to the Container Instance Resource Principal.  This method utilizes resource principal version 2.2. Please refer to  https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdk_authentication_methods.htm#sdk_authentication_methods_resource_principal  for detailed explanation of how to leverage the exposed resource principal elements.
         * 
         * @return builder
         * 
         */
        public Builder isResourcePrincipalDisabled(@Nullable Output<Boolean> isResourcePrincipalDisabled) {
            $.isResourcePrincipalDisabled = isResourcePrincipalDisabled;
            return this;
        }

        /**
         * @param isResourcePrincipalDisabled Determines if the Container will have access to the Container Instance Resource Principal.  This method utilizes resource principal version 2.2. Please refer to  https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdk_authentication_methods.htm#sdk_authentication_methods_resource_principal  for detailed explanation of how to leverage the exposed resource principal elements.
         * 
         * @return builder
         * 
         */
        public Builder isResourcePrincipalDisabled(Boolean isResourcePrincipalDisabled) {
            return isResourcePrincipalDisabled(Output.of(isResourcePrincipalDisabled));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param resourceConfig The size and amount of resources available to the Container.
         * 
         * @return builder
         * 
         */
        public Builder resourceConfig(@Nullable Output<ContainerInstanceContainerResourceConfigArgs> resourceConfig) {
            $.resourceConfig = resourceConfig;
            return this;
        }

        /**
         * @param resourceConfig The size and amount of resources available to the Container.
         * 
         * @return builder
         * 
         */
        public Builder resourceConfig(ContainerInstanceContainerResourceConfigArgs resourceConfig) {
            return resourceConfig(Output.of(resourceConfig));
        }

        /**
         * @param state (Updatable) The target state for the Container Instance. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The target state for the Container Instance. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,Object>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,Object> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time the the ContainerInstance was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the the ContainerInstance was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public Builder timeTerminated(@Nullable Output<String> timeTerminated) {
            $.timeTerminated = timeTerminated;
            return this;
        }

        public Builder timeTerminated(String timeTerminated) {
            return timeTerminated(Output.of(timeTerminated));
        }

        /**
         * @param timeUpdated The time the ContainerInstance was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the ContainerInstance was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param volumeMounts List of the volume mounts.
         * 
         * @return builder
         * 
         */
        public Builder volumeMounts(@Nullable Output<List<ContainerInstanceContainerVolumeMountArgs>> volumeMounts) {
            $.volumeMounts = volumeMounts;
            return this;
        }

        /**
         * @param volumeMounts List of the volume mounts.
         * 
         * @return builder
         * 
         */
        public Builder volumeMounts(List<ContainerInstanceContainerVolumeMountArgs> volumeMounts) {
            return volumeMounts(Output.of(volumeMounts));
        }

        /**
         * @param volumeMounts List of the volume mounts.
         * 
         * @return builder
         * 
         */
        public Builder volumeMounts(ContainerInstanceContainerVolumeMountArgs... volumeMounts) {
            return volumeMounts(List.of(volumeMounts));
        }

        /**
         * @param workingDirectory The working directory within the Container&#39;s filesystem for the Container process. If none is set, the Container will run in the working directory set by the container image.
         * 
         * @return builder
         * 
         */
        public Builder workingDirectory(@Nullable Output<String> workingDirectory) {
            $.workingDirectory = workingDirectory;
            return this;
        }

        /**
         * @param workingDirectory The working directory within the Container&#39;s filesystem for the Container process. If none is set, the Container will run in the working directory set by the container image.
         * 
         * @return builder
         * 
         */
        public Builder workingDirectory(String workingDirectory) {
            return workingDirectory(Output.of(workingDirectory));
        }

        public ContainerInstanceContainerArgs build() {
            $.imageUrl = Objects.requireNonNull($.imageUrl, "expected parameter 'imageUrl' to be non-null");
            return $;
        }
    }

}