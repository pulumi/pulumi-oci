// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceAliasesArgs;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceCredentialsArgs;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceDatabaseConnectionDetailsArgs;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourcePropertyArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoredResourceState extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceState Empty = new MonitoredResourceState();

    /**
     * (Updatable) Monitored Resource Alias Credential Details
     * 
     */
    @Import(name="aliases")
    private @Nullable Output<MonitoredResourceAliasesArgs> aliases;

    /**
     * @return (Updatable) Monitored Resource Alias Credential Details
     * 
     */
    public Optional<Output<MonitoredResourceAliasesArgs>> aliases() {
        return Optional.ofNullable(this.aliases);
    }

    /**
     * (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Monitored Resource Credential Details
     * 
     */
    @Import(name="credentials")
    private @Nullable Output<MonitoredResourceCredentialsArgs> credentials;

    /**
     * @return (Updatable) Monitored Resource Credential Details
     * 
     */
    public Optional<Output<MonitoredResourceCredentialsArgs>> credentials() {
        return Optional.ofNullable(this.credentials);
    }

    /**
     * (Updatable) Connection details to connect to the database. HostName, protocol, and port should be specified.
     * 
     */
    @Import(name="databaseConnectionDetails")
    private @Nullable Output<MonitoredResourceDatabaseConnectionDetailsArgs> databaseConnectionDetails;

    /**
     * @return (Updatable) Connection details to connect to the database. HostName, protocol, and port should be specified.
     * 
     */
    public Optional<Output<MonitoredResourceDatabaseConnectionDetailsArgs>> databaseConnectionDetails() {
        return Optional.ofNullable(this.databaseConnectionDetails);
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
     * (Updatable) Monitored resource display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Monitored resource display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Generally used by DBaaS to send the Database OCID stored on the DBaaS. The same will be passed to resource service to enable Stack Monitoring Service on DBM. This will be stored in Stack Monitoring Resource Service data store as identifier for monitored resource. If this header is not set as part of the request, then an id will be generated and stored for the resource.
     * 
     */
    @Import(name="externalResourceId")
    private @Nullable Output<String> externalResourceId;

    /**
     * @return Generally used by DBaaS to send the Database OCID stored on the DBaaS. The same will be passed to resource service to enable Stack Monitoring Service on DBM. This will be stored in Stack Monitoring Resource Service data store as identifier for monitored resource. If this header is not set as part of the request, then an id will be generated and stored for the resource.
     * 
     */
    public Optional<Output<String>> externalResourceId() {
        return Optional.ofNullable(this.externalResourceId);
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
     * (Updatable) Host name of the monitored resource
     * 
     */
    @Import(name="hostName")
    private @Nullable Output<String> hostName;

    /**
     * @return (Updatable) Host name of the monitored resource
     * 
     */
    public Optional<Output<String>> hostName() {
        return Optional.ofNullable(this.hostName);
    }

    /**
     * Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="managementAgentId")
    private @Nullable Output<String> managementAgentId;

    /**
     * @return Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> managementAgentId() {
        return Optional.ofNullable(this.managementAgentId);
    }

    /**
     * (Updatable) property name
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) property name
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) List of monitored resource properties
     * 
     */
    @Import(name="properties")
    private @Nullable Output<List<MonitoredResourcePropertyArgs>> properties;

    /**
     * @return (Updatable) List of monitored resource properties
     * 
     */
    public Optional<Output<List<MonitoredResourcePropertyArgs>>> properties() {
        return Optional.ofNullable(this.properties);
    }

    /**
     * (Updatable) Time zone in the form of tz database canonical zone ID.
     * 
     */
    @Import(name="resourceTimeZone")
    private @Nullable Output<String> resourceTimeZone;

    /**
     * @return (Updatable) Time zone in the form of tz database canonical zone ID.
     * 
     */
    public Optional<Output<String>> resourceTimeZone() {
        return Optional.ofNullable(this.resourceTimeZone);
    }

    /**
     * Lifecycle state of the monitored resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return Lifecycle state of the monitored resource.
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
     * Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Import(name="tenantId")
    private @Nullable Output<String> tenantId;

    /**
     * @return Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Optional<Output<String>> tenantId() {
        return Optional.ofNullable(this.tenantId);
    }

    /**
     * The time the the resource was created. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the the resource was created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the the resource was updated. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the the resource was updated. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * Monitored resource type
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return Monitored resource type
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private MonitoredResourceState() {}

    private MonitoredResourceState(MonitoredResourceState $) {
        this.aliases = $.aliases;
        this.compartmentId = $.compartmentId;
        this.credentials = $.credentials;
        this.databaseConnectionDetails = $.databaseConnectionDetails;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.externalResourceId = $.externalResourceId;
        this.freeformTags = $.freeformTags;
        this.hostName = $.hostName;
        this.managementAgentId = $.managementAgentId;
        this.name = $.name;
        this.properties = $.properties;
        this.resourceTimeZone = $.resourceTimeZone;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.tenantId = $.tenantId;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceState $;

        public Builder() {
            $ = new MonitoredResourceState();
        }

        public Builder(MonitoredResourceState defaults) {
            $ = new MonitoredResourceState(Objects.requireNonNull(defaults));
        }

        /**
         * @param aliases (Updatable) Monitored Resource Alias Credential Details
         * 
         * @return builder
         * 
         */
        public Builder aliases(@Nullable Output<MonitoredResourceAliasesArgs> aliases) {
            $.aliases = aliases;
            return this;
        }

        /**
         * @param aliases (Updatable) Monitored Resource Alias Credential Details
         * 
         * @return builder
         * 
         */
        public Builder aliases(MonitoredResourceAliasesArgs aliases) {
            return aliases(Output.of(aliases));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param credentials (Updatable) Monitored Resource Credential Details
         * 
         * @return builder
         * 
         */
        public Builder credentials(@Nullable Output<MonitoredResourceCredentialsArgs> credentials) {
            $.credentials = credentials;
            return this;
        }

        /**
         * @param credentials (Updatable) Monitored Resource Credential Details
         * 
         * @return builder
         * 
         */
        public Builder credentials(MonitoredResourceCredentialsArgs credentials) {
            return credentials(Output.of(credentials));
        }

        /**
         * @param databaseConnectionDetails (Updatable) Connection details to connect to the database. HostName, protocol, and port should be specified.
         * 
         * @return builder
         * 
         */
        public Builder databaseConnectionDetails(@Nullable Output<MonitoredResourceDatabaseConnectionDetailsArgs> databaseConnectionDetails) {
            $.databaseConnectionDetails = databaseConnectionDetails;
            return this;
        }

        /**
         * @param databaseConnectionDetails (Updatable) Connection details to connect to the database. HostName, protocol, and port should be specified.
         * 
         * @return builder
         * 
         */
        public Builder databaseConnectionDetails(MonitoredResourceDatabaseConnectionDetailsArgs databaseConnectionDetails) {
            return databaseConnectionDetails(Output.of(databaseConnectionDetails));
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
         * @param displayName (Updatable) Monitored resource display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Monitored resource display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalResourceId Generally used by DBaaS to send the Database OCID stored on the DBaaS. The same will be passed to resource service to enable Stack Monitoring Service on DBM. This will be stored in Stack Monitoring Resource Service data store as identifier for monitored resource. If this header is not set as part of the request, then an id will be generated and stored for the resource.
         * 
         * @return builder
         * 
         */
        public Builder externalResourceId(@Nullable Output<String> externalResourceId) {
            $.externalResourceId = externalResourceId;
            return this;
        }

        /**
         * @param externalResourceId Generally used by DBaaS to send the Database OCID stored on the DBaaS. The same will be passed to resource service to enable Stack Monitoring Service on DBM. This will be stored in Stack Monitoring Resource Service data store as identifier for monitored resource. If this header is not set as part of the request, then an id will be generated and stored for the resource.
         * 
         * @return builder
         * 
         */
        public Builder externalResourceId(String externalResourceId) {
            return externalResourceId(Output.of(externalResourceId));
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
         * @param hostName (Updatable) Host name of the monitored resource
         * 
         * @return builder
         * 
         */
        public Builder hostName(@Nullable Output<String> hostName) {
            $.hostName = hostName;
            return this;
        }

        /**
         * @param hostName (Updatable) Host name of the monitored resource
         * 
         * @return builder
         * 
         */
        public Builder hostName(String hostName) {
            return hostName(Output.of(hostName));
        }

        /**
         * @param managementAgentId Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder managementAgentId(@Nullable Output<String> managementAgentId) {
            $.managementAgentId = managementAgentId;
            return this;
        }

        /**
         * @param managementAgentId Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder managementAgentId(String managementAgentId) {
            return managementAgentId(Output.of(managementAgentId));
        }

        /**
         * @param name (Updatable) property name
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) property name
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param properties (Updatable) List of monitored resource properties
         * 
         * @return builder
         * 
         */
        public Builder properties(@Nullable Output<List<MonitoredResourcePropertyArgs>> properties) {
            $.properties = properties;
            return this;
        }

        /**
         * @param properties (Updatable) List of monitored resource properties
         * 
         * @return builder
         * 
         */
        public Builder properties(List<MonitoredResourcePropertyArgs> properties) {
            return properties(Output.of(properties));
        }

        /**
         * @param properties (Updatable) List of monitored resource properties
         * 
         * @return builder
         * 
         */
        public Builder properties(MonitoredResourcePropertyArgs... properties) {
            return properties(List.of(properties));
        }

        /**
         * @param resourceTimeZone (Updatable) Time zone in the form of tz database canonical zone ID.
         * 
         * @return builder
         * 
         */
        public Builder resourceTimeZone(@Nullable Output<String> resourceTimeZone) {
            $.resourceTimeZone = resourceTimeZone;
            return this;
        }

        /**
         * @param resourceTimeZone (Updatable) Time zone in the form of tz database canonical zone ID.
         * 
         * @return builder
         * 
         */
        public Builder resourceTimeZone(String resourceTimeZone) {
            return resourceTimeZone(Output.of(resourceTimeZone));
        }

        /**
         * @param state Lifecycle state of the monitored resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state Lifecycle state of the monitored resource.
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
         * @param tenantId Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder tenantId(@Nullable Output<String> tenantId) {
            $.tenantId = tenantId;
            return this;
        }

        /**
         * @param tenantId Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder tenantId(String tenantId) {
            return tenantId(Output.of(tenantId));
        }

        /**
         * @param timeCreated The time the the resource was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the the resource was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the the resource was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the the resource was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param type Monitored resource type
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Monitored resource type
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public MonitoredResourceState build() {
            return $;
        }
    }

}