// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LogAnalytics.inputs.LogAnalyticsEntityMetadataArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class LogAnalyticsEntityState extends com.pulumi.resources.ResourceArgs {

    public static final LogAnalyticsEntityState Empty = new LogAnalyticsEntityState();

    /**
     * The Boolean flag to indicate if logs are collected for an entity for log analytics usage.
     * 
     */
    @Import(name="areLogsCollected")
    private @Nullable Output<Boolean> areLogsCollected;

    /**
     * @return The Boolean flag to indicate if logs are collected for an entity for log analytics usage.
     * 
     */
    public Optional<Output<Boolean>> areLogsCollected() {
        return Optional.ofNullable(this.areLogsCollected);
    }

    /**
     * The count of associated log sources for a given log analytics entity.
     * 
     */
    @Import(name="associatedSourcesCount")
    private @Nullable Output<Integer> associatedSourcesCount;

    /**
     * @return The count of associated log sources for a given log analytics entity.
     * 
     */
    public Optional<Output<Integer>> associatedSourcesCount() {
        return Optional.ofNullable(this.associatedSourcesCount);
    }

    /**
     * The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
     * 
     */
    @Import(name="cloudResourceId")
    private @Nullable Output<String> cloudResourceId;

    /**
     * @return The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
     * 
     */
    public Optional<Output<String>> cloudResourceId() {
        return Optional.ofNullable(this.cloudResourceId);
    }

    /**
     * (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
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
     * Internal name for the log analytics entity type.
     * 
     */
    @Import(name="entityTypeInternalName")
    private @Nullable Output<String> entityTypeInternalName;

    /**
     * @return Internal name for the log analytics entity type.
     * 
     */
    public Optional<Output<String>> entityTypeInternalName() {
        return Optional.ofNullable(this.entityTypeInternalName);
    }

    /**
     * Log analytics entity type name.
     * 
     */
    @Import(name="entityTypeName")
    private @Nullable Output<String> entityTypeName;

    /**
     * @return Log analytics entity type name.
     * 
     */
    public Optional<Output<String>> entityTypeName() {
        return Optional.ofNullable(this.entityTypeName);
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
     * (Updatable) The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
     * 
     */
    @Import(name="hostname")
    private @Nullable Output<String> hostname;

    /**
     * @return (Updatable) The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
     * 
     */
    public Optional<Output<String>> hostname() {
        return Optional.ofNullable(this.hostname);
    }

    /**
     * lifecycleDetails has additional information regarding substeps such as management agent plugin deployment.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return lifecycleDetails has additional information regarding substeps such as management agent plugin deployment.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * Management agent (management-agents resource kind) compartment OCID
     * 
     */
    @Import(name="managementAgentCompartmentId")
    private @Nullable Output<String> managementAgentCompartmentId;

    /**
     * @return Management agent (management-agents resource kind) compartment OCID
     * 
     */
    public Optional<Output<String>> managementAgentCompartmentId() {
        return Optional.ofNullable(this.managementAgentCompartmentId);
    }

    /**
     * Management agent (management-agents resource kind) display name
     * 
     */
    @Import(name="managementAgentDisplayName")
    private @Nullable Output<String> managementAgentDisplayName;

    /**
     * @return Management agent (management-agents resource kind) display name
     * 
     */
    public Optional<Output<String>> managementAgentDisplayName() {
        return Optional.ofNullable(this.managementAgentDisplayName);
    }

    /**
     * (Updatable) The OCID of the Management Agent.
     * 
     */
    @Import(name="managementAgentId")
    private @Nullable Output<String> managementAgentId;

    /**
     * @return (Updatable) The OCID of the Management Agent.
     * 
     */
    public Optional<Output<String>> managementAgentId() {
        return Optional.ofNullable(this.managementAgentId);
    }

    /**
     * (Updatable) Details of Entity Metadata.
     * 
     */
    @Import(name="metadata")
    private @Nullable Output<LogAnalyticsEntityMetadataArgs> metadata;

    /**
     * @return (Updatable) Details of Entity Metadata.
     * 
     */
    public Optional<Output<LogAnalyticsEntityMetadataArgs>> metadata() {
        return Optional.ofNullable(this.metadata);
    }

    /**
     * (Updatable) Log analytics entity name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Log analytics entity name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * (Updatable) The name/value pairs for parameter values to be used in file patterns specified in log sources.
     * 
     */
    @Import(name="properties")
    private @Nullable Output<Map<String,String>> properties;

    /**
     * @return (Updatable) The name/value pairs for parameter values to be used in file patterns specified in log sources.
     * 
     */
    public Optional<Output<Map<String,String>>> properties() {
        return Optional.ofNullable(this.properties);
    }

    /**
     * This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
     * 
     */
    @Import(name="sourceId")
    private @Nullable Output<String> sourceId;

    /**
     * @return This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
     * 
     */
    public Optional<Output<String>> sourceId() {
        return Optional.ofNullable(this.sourceId);
    }

    /**
     * The current state of the log analytics entity.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the log analytics entity.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the resource was created, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * (Updatable) The date and time the resource was last discovered, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeLastDiscovered")
    private @Nullable Output<String> timeLastDiscovered;

    /**
     * @return (Updatable) The date and time the resource was last discovered, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeLastDiscovered() {
        return Optional.ofNullable(this.timeLastDiscovered);
    }

    /**
     * The date and time the resource was last updated, in the format defined by RFC3339.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the resource was last updated, in the format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * (Updatable) The timezone region of the log analytics entity.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="timezoneRegion")
    private @Nullable Output<String> timezoneRegion;

    /**
     * @return (Updatable) The timezone region of the log analytics entity.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> timezoneRegion() {
        return Optional.ofNullable(this.timezoneRegion);
    }

    private LogAnalyticsEntityState() {}

    private LogAnalyticsEntityState(LogAnalyticsEntityState $) {
        this.areLogsCollected = $.areLogsCollected;
        this.associatedSourcesCount = $.associatedSourcesCount;
        this.cloudResourceId = $.cloudResourceId;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.entityTypeInternalName = $.entityTypeInternalName;
        this.entityTypeName = $.entityTypeName;
        this.freeformTags = $.freeformTags;
        this.hostname = $.hostname;
        this.lifecycleDetails = $.lifecycleDetails;
        this.managementAgentCompartmentId = $.managementAgentCompartmentId;
        this.managementAgentDisplayName = $.managementAgentDisplayName;
        this.managementAgentId = $.managementAgentId;
        this.metadata = $.metadata;
        this.name = $.name;
        this.namespace = $.namespace;
        this.properties = $.properties;
        this.sourceId = $.sourceId;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeLastDiscovered = $.timeLastDiscovered;
        this.timeUpdated = $.timeUpdated;
        this.timezoneRegion = $.timezoneRegion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(LogAnalyticsEntityState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private LogAnalyticsEntityState $;

        public Builder() {
            $ = new LogAnalyticsEntityState();
        }

        public Builder(LogAnalyticsEntityState defaults) {
            $ = new LogAnalyticsEntityState(Objects.requireNonNull(defaults));
        }

        /**
         * @param areLogsCollected The Boolean flag to indicate if logs are collected for an entity for log analytics usage.
         * 
         * @return builder
         * 
         */
        public Builder areLogsCollected(@Nullable Output<Boolean> areLogsCollected) {
            $.areLogsCollected = areLogsCollected;
            return this;
        }

        /**
         * @param areLogsCollected The Boolean flag to indicate if logs are collected for an entity for log analytics usage.
         * 
         * @return builder
         * 
         */
        public Builder areLogsCollected(Boolean areLogsCollected) {
            return areLogsCollected(Output.of(areLogsCollected));
        }

        /**
         * @param associatedSourcesCount The count of associated log sources for a given log analytics entity.
         * 
         * @return builder
         * 
         */
        public Builder associatedSourcesCount(@Nullable Output<Integer> associatedSourcesCount) {
            $.associatedSourcesCount = associatedSourcesCount;
            return this;
        }

        /**
         * @param associatedSourcesCount The count of associated log sources for a given log analytics entity.
         * 
         * @return builder
         * 
         */
        public Builder associatedSourcesCount(Integer associatedSourcesCount) {
            return associatedSourcesCount(Output.of(associatedSourcesCount));
        }

        /**
         * @param cloudResourceId The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
         * 
         * @return builder
         * 
         */
        public Builder cloudResourceId(@Nullable Output<String> cloudResourceId) {
            $.cloudResourceId = cloudResourceId;
            return this;
        }

        /**
         * @param cloudResourceId The OCID of the Cloud resource which this entity is a representation of. This may be blank when the entity represents a non-cloud resource that the customer may have on their premises.
         * 
         * @return builder
         * 
         */
        public Builder cloudResourceId(String cloudResourceId) {
            return cloudResourceId(Output.of(cloudResourceId));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
         * @param entityTypeInternalName Internal name for the log analytics entity type.
         * 
         * @return builder
         * 
         */
        public Builder entityTypeInternalName(@Nullable Output<String> entityTypeInternalName) {
            $.entityTypeInternalName = entityTypeInternalName;
            return this;
        }

        /**
         * @param entityTypeInternalName Internal name for the log analytics entity type.
         * 
         * @return builder
         * 
         */
        public Builder entityTypeInternalName(String entityTypeInternalName) {
            return entityTypeInternalName(Output.of(entityTypeInternalName));
        }

        /**
         * @param entityTypeName Log analytics entity type name.
         * 
         * @return builder
         * 
         */
        public Builder entityTypeName(@Nullable Output<String> entityTypeName) {
            $.entityTypeName = entityTypeName;
            return this;
        }

        /**
         * @param entityTypeName Log analytics entity type name.
         * 
         * @return builder
         * 
         */
        public Builder entityTypeName(String entityTypeName) {
            return entityTypeName(Output.of(entityTypeName));
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
         * @param hostname (Updatable) The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
         * 
         * @return builder
         * 
         */
        public Builder hostname(@Nullable Output<String> hostname) {
            $.hostname = hostname;
            return this;
        }

        /**
         * @param hostname (Updatable) The hostname where the entity represented here is actually present. This would be the output one would get if they run `echo $HOSTNAME` on Linux or an equivalent OS command. This may be different from management agents host since logs may be collected remotely.
         * 
         * @return builder
         * 
         */
        public Builder hostname(String hostname) {
            return hostname(Output.of(hostname));
        }

        /**
         * @param lifecycleDetails lifecycleDetails has additional information regarding substeps such as management agent plugin deployment.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails lifecycleDetails has additional information regarding substeps such as management agent plugin deployment.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param managementAgentCompartmentId Management agent (management-agents resource kind) compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder managementAgentCompartmentId(@Nullable Output<String> managementAgentCompartmentId) {
            $.managementAgentCompartmentId = managementAgentCompartmentId;
            return this;
        }

        /**
         * @param managementAgentCompartmentId Management agent (management-agents resource kind) compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder managementAgentCompartmentId(String managementAgentCompartmentId) {
            return managementAgentCompartmentId(Output.of(managementAgentCompartmentId));
        }

        /**
         * @param managementAgentDisplayName Management agent (management-agents resource kind) display name
         * 
         * @return builder
         * 
         */
        public Builder managementAgentDisplayName(@Nullable Output<String> managementAgentDisplayName) {
            $.managementAgentDisplayName = managementAgentDisplayName;
            return this;
        }

        /**
         * @param managementAgentDisplayName Management agent (management-agents resource kind) display name
         * 
         * @return builder
         * 
         */
        public Builder managementAgentDisplayName(String managementAgentDisplayName) {
            return managementAgentDisplayName(Output.of(managementAgentDisplayName));
        }

        /**
         * @param managementAgentId (Updatable) The OCID of the Management Agent.
         * 
         * @return builder
         * 
         */
        public Builder managementAgentId(@Nullable Output<String> managementAgentId) {
            $.managementAgentId = managementAgentId;
            return this;
        }

        /**
         * @param managementAgentId (Updatable) The OCID of the Management Agent.
         * 
         * @return builder
         * 
         */
        public Builder managementAgentId(String managementAgentId) {
            return managementAgentId(Output.of(managementAgentId));
        }

        /**
         * @param metadata (Updatable) Details of Entity Metadata.
         * 
         * @return builder
         * 
         */
        public Builder metadata(@Nullable Output<LogAnalyticsEntityMetadataArgs> metadata) {
            $.metadata = metadata;
            return this;
        }

        /**
         * @param metadata (Updatable) Details of Entity Metadata.
         * 
         * @return builder
         * 
         */
        public Builder metadata(LogAnalyticsEntityMetadataArgs metadata) {
            return metadata(Output.of(metadata));
        }

        /**
         * @param name (Updatable) Log analytics entity name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Log analytics entity name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param properties (Updatable) The name/value pairs for parameter values to be used in file patterns specified in log sources.
         * 
         * @return builder
         * 
         */
        public Builder properties(@Nullable Output<Map<String,String>> properties) {
            $.properties = properties;
            return this;
        }

        /**
         * @param properties (Updatable) The name/value pairs for parameter values to be used in file patterns specified in log sources.
         * 
         * @return builder
         * 
         */
        public Builder properties(Map<String,String> properties) {
            return properties(Output.of(properties));
        }

        /**
         * @param sourceId This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
         * 
         * @return builder
         * 
         */
        public Builder sourceId(@Nullable Output<String> sourceId) {
            $.sourceId = sourceId;
            return this;
        }

        /**
         * @param sourceId This indicates the type of source. It is primarily for Enterprise Manager Repository ID.
         * 
         * @return builder
         * 
         */
        public Builder sourceId(String sourceId) {
            return sourceId(Output.of(sourceId));
        }

        /**
         * @param state The current state of the log analytics entity.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the log analytics entity.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the resource was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the resource was created, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeLastDiscovered (Updatable) The date and time the resource was last discovered, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastDiscovered(@Nullable Output<String> timeLastDiscovered) {
            $.timeLastDiscovered = timeLastDiscovered;
            return this;
        }

        /**
         * @param timeLastDiscovered (Updatable) The date and time the resource was last discovered, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastDiscovered(String timeLastDiscovered) {
            return timeLastDiscovered(Output.of(timeLastDiscovered));
        }

        /**
         * @param timeUpdated The date and time the resource was last updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the resource was last updated, in the format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param timezoneRegion (Updatable) The timezone region of the log analytics entity.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timezoneRegion(@Nullable Output<String> timezoneRegion) {
            $.timezoneRegion = timezoneRegion;
            return this;
        }

        /**
         * @param timezoneRegion (Updatable) The timezone region of the log analytics entity.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timezoneRegion(String timezoneRegion) {
            return timezoneRegion(Output.of(timezoneRegion));
        }

        public LogAnalyticsEntityState build() {
            return $;
        }
    }

}
