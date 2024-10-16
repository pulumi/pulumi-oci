// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AwrHubSourceState extends com.pulumi.resources.ResourceArgs {

    public static final AwrHubSourceState Empty = new AwrHubSourceState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    @Import(name="associatedOpsiId")
    private @Nullable Output<String> associatedOpsiId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    public Optional<Output<String>> associatedOpsiId() {
        return Optional.ofNullable(this.associatedOpsiId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    @Import(name="associatedResourceId")
    private @Nullable Output<String> associatedResourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    public Optional<Output<String>> associatedResourceId() {
        return Optional.ofNullable(this.associatedResourceId);
    }

    /**
     * AWR Hub OCID
     * 
     */
    @Import(name="awrHubId")
    private @Nullable Output<String> awrHubId;

    /**
     * @return AWR Hub OCID
     * 
     */
    public Optional<Output<String>> awrHubId() {
        return Optional.ofNullable(this.awrHubId);
    }

    /**
     * The shorted string of the Awr Hub source database identifier.
     * 
     */
    @Import(name="awrHubOpsiSourceId")
    private @Nullable Output<String> awrHubOpsiSourceId;

    /**
     * @return The shorted string of the Awr Hub source database identifier.
     * 
     */
    public Optional<Output<String>> awrHubOpsiSourceId() {
        return Optional.ofNullable(this.awrHubOpsiSourceId);
    }

    /**
     * DatabaseId of the Source database for which AWR Data will be uploaded to AWR Hub.
     * 
     */
    @Import(name="awrSourceDatabaseId")
    private @Nullable Output<String> awrSourceDatabaseId;

    /**
     * @return DatabaseId of the Source database for which AWR Data will be uploaded to AWR Hub.
     * 
     */
    public Optional<Output<String>> awrSourceDatabaseId() {
        return Optional.ofNullable(this.awrSourceDatabaseId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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
     * Number of hours since last AWR snapshots import happened from the Source database.
     * 
     */
    @Import(name="hoursSinceLastImport")
    private @Nullable Output<Double> hoursSinceLastImport;

    /**
     * @return Number of hours since last AWR snapshots import happened from the Source database.
     * 
     */
    public Optional<Output<Double>> hoursSinceLastImport() {
        return Optional.ofNullable(this.hoursSinceLastImport);
    }

    /**
     * This is `true` if the source databse is registered with a Awr Hub, otherwise `false`
     * 
     */
    @Import(name="isRegisteredWithAwrHub")
    private @Nullable Output<Boolean> isRegisteredWithAwrHub;

    /**
     * @return This is `true` if the source databse is registered with a Awr Hub, otherwise `false`
     * 
     */
    public Optional<Output<Boolean>> isRegisteredWithAwrHub() {
        return Optional.ofNullable(this.isRegisteredWithAwrHub);
    }

    /**
     * The maximum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
     * 
     */
    @Import(name="maxSnapshotIdentifier")
    private @Nullable Output<Double> maxSnapshotIdentifier;

    /**
     * @return The maximum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
     * 
     */
    public Optional<Output<Double>> maxSnapshotIdentifier() {
        return Optional.ofNullable(this.maxSnapshotIdentifier);
    }

    /**
     * The minimum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
     * 
     */
    @Import(name="minSnapshotIdentifier")
    private @Nullable Output<Double> minSnapshotIdentifier;

    /**
     * @return The minimum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
     * 
     */
    public Optional<Output<Double>> minSnapshotIdentifier() {
        return Optional.ofNullable(this.minSnapshotIdentifier);
    }

    /**
     * The name of the Awr Hub source database.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the Awr Hub source database.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Opsi Mailbox URL based on the Awr Hub and Awr Hub source.
     * 
     */
    @Import(name="sourceMailBoxUrl")
    private @Nullable Output<String> sourceMailBoxUrl;

    /**
     * @return Opsi Mailbox URL based on the Awr Hub and Awr Hub source.
     * 
     */
    public Optional<Output<String>> sourceMailBoxUrl() {
        return Optional.ofNullable(this.sourceMailBoxUrl);
    }

    /**
     * the current state of the source database
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return the current state of the source database
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Indicates the status of a source database in Operations Insights
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return Indicates the status of a source database in Operations Insights
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time at which the resource was first created. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time at which the resource was first created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time at which the earliest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeFirstSnapshotGenerated")
    private @Nullable Output<String> timeFirstSnapshotGenerated;

    /**
     * @return The time at which the earliest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeFirstSnapshotGenerated() {
        return Optional.ofNullable(this.timeFirstSnapshotGenerated);
    }

    /**
     * The time at which the latest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeLastSnapshotGenerated")
    private @Nullable Output<String> timeLastSnapshotGenerated;

    /**
     * @return The time at which the latest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeLastSnapshotGenerated() {
        return Optional.ofNullable(this.timeLastSnapshotGenerated);
    }

    /**
     * The time at which the resource was last updated. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time at which the resource was last updated. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * (Updatable) source type of the database
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) source type of the database
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private AwrHubSourceState() {}

    private AwrHubSourceState(AwrHubSourceState $) {
        this.associatedOpsiId = $.associatedOpsiId;
        this.associatedResourceId = $.associatedResourceId;
        this.awrHubId = $.awrHubId;
        this.awrHubOpsiSourceId = $.awrHubOpsiSourceId;
        this.awrSourceDatabaseId = $.awrSourceDatabaseId;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.hoursSinceLastImport = $.hoursSinceLastImport;
        this.isRegisteredWithAwrHub = $.isRegisteredWithAwrHub;
        this.maxSnapshotIdentifier = $.maxSnapshotIdentifier;
        this.minSnapshotIdentifier = $.minSnapshotIdentifier;
        this.name = $.name;
        this.sourceMailBoxUrl = $.sourceMailBoxUrl;
        this.state = $.state;
        this.status = $.status;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeFirstSnapshotGenerated = $.timeFirstSnapshotGenerated;
        this.timeLastSnapshotGenerated = $.timeLastSnapshotGenerated;
        this.timeUpdated = $.timeUpdated;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AwrHubSourceState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AwrHubSourceState $;

        public Builder() {
            $ = new AwrHubSourceState();
        }

        public Builder(AwrHubSourceState defaults) {
            $ = new AwrHubSourceState(Objects.requireNonNull(defaults));
        }

        /**
         * @param associatedOpsiId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedOpsiId(@Nullable Output<String> associatedOpsiId) {
            $.associatedOpsiId = associatedOpsiId;
            return this;
        }

        /**
         * @param associatedOpsiId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedOpsiId(String associatedOpsiId) {
            return associatedOpsiId(Output.of(associatedOpsiId));
        }

        /**
         * @param associatedResourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedResourceId(@Nullable Output<String> associatedResourceId) {
            $.associatedResourceId = associatedResourceId;
            return this;
        }

        /**
         * @param associatedResourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedResourceId(String associatedResourceId) {
            return associatedResourceId(Output.of(associatedResourceId));
        }

        /**
         * @param awrHubId AWR Hub OCID
         * 
         * @return builder
         * 
         */
        public Builder awrHubId(@Nullable Output<String> awrHubId) {
            $.awrHubId = awrHubId;
            return this;
        }

        /**
         * @param awrHubId AWR Hub OCID
         * 
         * @return builder
         * 
         */
        public Builder awrHubId(String awrHubId) {
            return awrHubId(Output.of(awrHubId));
        }

        /**
         * @param awrHubOpsiSourceId The shorted string of the Awr Hub source database identifier.
         * 
         * @return builder
         * 
         */
        public Builder awrHubOpsiSourceId(@Nullable Output<String> awrHubOpsiSourceId) {
            $.awrHubOpsiSourceId = awrHubOpsiSourceId;
            return this;
        }

        /**
         * @param awrHubOpsiSourceId The shorted string of the Awr Hub source database identifier.
         * 
         * @return builder
         * 
         */
        public Builder awrHubOpsiSourceId(String awrHubOpsiSourceId) {
            return awrHubOpsiSourceId(Output.of(awrHubOpsiSourceId));
        }

        /**
         * @param awrSourceDatabaseId DatabaseId of the Source database for which AWR Data will be uploaded to AWR Hub.
         * 
         * @return builder
         * 
         */
        public Builder awrSourceDatabaseId(@Nullable Output<String> awrSourceDatabaseId) {
            $.awrSourceDatabaseId = awrSourceDatabaseId;
            return this;
        }

        /**
         * @param awrSourceDatabaseId DatabaseId of the Source database for which AWR Data will be uploaded to AWR Hub.
         * 
         * @return builder
         * 
         */
        public Builder awrSourceDatabaseId(String awrSourceDatabaseId) {
            return awrSourceDatabaseId(Output.of(awrSourceDatabaseId));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
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
         * @param hoursSinceLastImport Number of hours since last AWR snapshots import happened from the Source database.
         * 
         * @return builder
         * 
         */
        public Builder hoursSinceLastImport(@Nullable Output<Double> hoursSinceLastImport) {
            $.hoursSinceLastImport = hoursSinceLastImport;
            return this;
        }

        /**
         * @param hoursSinceLastImport Number of hours since last AWR snapshots import happened from the Source database.
         * 
         * @return builder
         * 
         */
        public Builder hoursSinceLastImport(Double hoursSinceLastImport) {
            return hoursSinceLastImport(Output.of(hoursSinceLastImport));
        }

        /**
         * @param isRegisteredWithAwrHub This is `true` if the source databse is registered with a Awr Hub, otherwise `false`
         * 
         * @return builder
         * 
         */
        public Builder isRegisteredWithAwrHub(@Nullable Output<Boolean> isRegisteredWithAwrHub) {
            $.isRegisteredWithAwrHub = isRegisteredWithAwrHub;
            return this;
        }

        /**
         * @param isRegisteredWithAwrHub This is `true` if the source databse is registered with a Awr Hub, otherwise `false`
         * 
         * @return builder
         * 
         */
        public Builder isRegisteredWithAwrHub(Boolean isRegisteredWithAwrHub) {
            return isRegisteredWithAwrHub(Output.of(isRegisteredWithAwrHub));
        }

        /**
         * @param maxSnapshotIdentifier The maximum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
         * 
         * @return builder
         * 
         */
        public Builder maxSnapshotIdentifier(@Nullable Output<Double> maxSnapshotIdentifier) {
            $.maxSnapshotIdentifier = maxSnapshotIdentifier;
            return this;
        }

        /**
         * @param maxSnapshotIdentifier The maximum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
         * 
         * @return builder
         * 
         */
        public Builder maxSnapshotIdentifier(Double maxSnapshotIdentifier) {
            return maxSnapshotIdentifier(Output.of(maxSnapshotIdentifier));
        }

        /**
         * @param minSnapshotIdentifier The minimum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
         * 
         * @return builder
         * 
         */
        public Builder minSnapshotIdentifier(@Nullable Output<Double> minSnapshotIdentifier) {
            $.minSnapshotIdentifier = minSnapshotIdentifier;
            return this;
        }

        /**
         * @param minSnapshotIdentifier The minimum snapshot identifier of the source database for which AWR data is uploaded to AWR Hub.
         * 
         * @return builder
         * 
         */
        public Builder minSnapshotIdentifier(Double minSnapshotIdentifier) {
            return minSnapshotIdentifier(Output.of(minSnapshotIdentifier));
        }

        /**
         * @param name The name of the Awr Hub source database.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the Awr Hub source database.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param sourceMailBoxUrl Opsi Mailbox URL based on the Awr Hub and Awr Hub source.
         * 
         * @return builder
         * 
         */
        public Builder sourceMailBoxUrl(@Nullable Output<String> sourceMailBoxUrl) {
            $.sourceMailBoxUrl = sourceMailBoxUrl;
            return this;
        }

        /**
         * @param sourceMailBoxUrl Opsi Mailbox URL based on the Awr Hub and Awr Hub source.
         * 
         * @return builder
         * 
         */
        public Builder sourceMailBoxUrl(String sourceMailBoxUrl) {
            return sourceMailBoxUrl(Output.of(sourceMailBoxUrl));
        }

        /**
         * @param state the current state of the source database
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state the current state of the source database
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param status Indicates the status of a source database in Operations Insights
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status Indicates the status of a source database in Operations Insights
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time at which the resource was first created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time at which the resource was first created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeFirstSnapshotGenerated The time at which the earliest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeFirstSnapshotGenerated(@Nullable Output<String> timeFirstSnapshotGenerated) {
            $.timeFirstSnapshotGenerated = timeFirstSnapshotGenerated;
            return this;
        }

        /**
         * @param timeFirstSnapshotGenerated The time at which the earliest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeFirstSnapshotGenerated(String timeFirstSnapshotGenerated) {
            return timeFirstSnapshotGenerated(Output.of(timeFirstSnapshotGenerated));
        }

        /**
         * @param timeLastSnapshotGenerated The time at which the latest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeLastSnapshotGenerated(@Nullable Output<String> timeLastSnapshotGenerated) {
            $.timeLastSnapshotGenerated = timeLastSnapshotGenerated;
            return this;
        }

        /**
         * @param timeLastSnapshotGenerated The time at which the latest snapshot was generated in the source database for which data is uploaded to AWR Hub. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeLastSnapshotGenerated(String timeLastSnapshotGenerated) {
            return timeLastSnapshotGenerated(Output.of(timeLastSnapshotGenerated));
        }

        /**
         * @param timeUpdated The time at which the resource was last updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time at which the resource was last updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param type (Updatable) source type of the database
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) source type of the database
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public AwrHubSourceState build() {
            return $;
        }
    }

}
