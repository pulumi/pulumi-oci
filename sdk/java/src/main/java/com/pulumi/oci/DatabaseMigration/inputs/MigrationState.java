// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationAdvancedParameterArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationAdvisorSettingsArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDataTransferMediumDetailsArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationExcludeObjectArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationGgsDetailsArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationHubDetailsArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationIncludeObjectArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationInitialLoadSettingsArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MigrationState extends com.pulumi.resources.ResourceArgs {

    public static final MigrationState Empty = new MigrationState();

    /**
     * (Updatable) List of Migration Parameter objects.
     * 
     */
    @Import(name="advancedParameters")
    private @Nullable Output<List<MigrationAdvancedParameterArgs>> advancedParameters;

    /**
     * @return (Updatable) List of Migration Parameter objects.
     * 
     */
    public Optional<Output<List<MigrationAdvancedParameterArgs>>> advancedParameters() {
        return Optional.ofNullable(this.advancedParameters);
    }

    /**
     * (Updatable) Optional Pre-Migration advisor settings.
     * 
     */
    @Import(name="advisorSettings")
    private @Nullable Output<MigrationAdvisorSettingsArgs> advisorSettings;

    /**
     * @return (Updatable) Optional Pre-Migration advisor settings.
     * 
     */
    public Optional<Output<MigrationAdvisorSettingsArgs>> advisorSettings() {
        return Optional.ofNullable(this.advisorSettings);
    }

    /**
     * Specifies the database objects to be excluded from the migration in bulk. The definition accepts input in a CSV format, newline separated for each entry. More details can be found in the documentation.
     * 
     */
    @Import(name="bulkIncludeExcludeData")
    private @Nullable Output<String> bulkIncludeExcludeData;

    /**
     * @return Specifies the database objects to be excluded from the migration in bulk. The definition accepts input in a CSV format, newline separated for each entry. More details can be found in the documentation.
     * 
     */
    public Optional<Output<String>> bulkIncludeExcludeData() {
        return Optional.ofNullable(this.bulkIncludeExcludeData);
    }

    /**
     * (Updatable) The OCID of the resource being referenced.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Optional additional properties for data transfer.
     * 
     */
    @Import(name="dataTransferMediumDetails")
    private @Nullable Output<MigrationDataTransferMediumDetailsArgs> dataTransferMediumDetails;

    /**
     * @return (Updatable) Optional additional properties for data transfer.
     * 
     */
    public Optional<Output<MigrationDataTransferMediumDetailsArgs>> dataTransferMediumDetails() {
        return Optional.ofNullable(this.dataTransferMediumDetails);
    }

    /**
     * (Updatable) The combination of source and target databases participating in a migration. Example: ORACLE means the migration is meant for migrating Oracle source and target databases.
     * 
     */
    @Import(name="databaseCombination")
    private @Nullable Output<String> databaseCombination;

    /**
     * @return (Updatable) The combination of source and target databases participating in a migration. Example: ORACLE means the migration is meant for migrating Oracle source and target databases.
     * 
     */
    public Optional<Output<String>> databaseCombination() {
        return Optional.ofNullable(this.databaseCombination);
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
     * (Updatable) A user-friendly description. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Database objects to exclude from migration, cannot be specified alongside &#39;includeObjects&#39;
     * 
     */
    @Import(name="excludeObjects")
    private @Nullable Output<List<MigrationExcludeObjectArgs>> excludeObjects;

    /**
     * @return Database objects to exclude from migration, cannot be specified alongside &#39;includeObjects&#39;
     * 
     */
    public Optional<Output<List<MigrationExcludeObjectArgs>>> excludeObjects() {
        return Optional.ofNullable(this.excludeObjects);
    }

    /**
     * The OCID of the resource being referenced.
     * 
     */
    @Import(name="executingJobId")
    private @Nullable Output<String> executingJobId;

    /**
     * @return The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> executingJobId() {
        return Optional.ofNullable(this.executingJobId);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {&#34;Department&#34;: &#34;Finance&#34;}
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {&#34;Department&#34;: &#34;Finance&#34;}
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Optional settings for Oracle GoldenGate processes
     * 
     */
    @Import(name="ggsDetails")
    private @Nullable Output<MigrationGgsDetailsArgs> ggsDetails;

    /**
     * @return (Updatable) Optional settings for Oracle GoldenGate processes
     * 
     */
    public Optional<Output<MigrationGgsDetailsArgs>> ggsDetails() {
        return Optional.ofNullable(this.ggsDetails);
    }

    /**
     * (Updatable) Details about Oracle GoldenGate Microservices.
     * 
     */
    @Import(name="hubDetails")
    private @Nullable Output<MigrationHubDetailsArgs> hubDetails;

    /**
     * @return (Updatable) Details about Oracle GoldenGate Microservices.
     * 
     */
    public Optional<Output<MigrationHubDetailsArgs>> hubDetails() {
        return Optional.ofNullable(this.hubDetails);
    }

    /**
     * Database objects to include from migration, cannot be specified alongside &#39;excludeObjects&#39;
     * 
     */
    @Import(name="includeObjects")
    private @Nullable Output<List<MigrationIncludeObjectArgs>> includeObjects;

    /**
     * @return Database objects to include from migration, cannot be specified alongside &#39;excludeObjects&#39;
     * 
     */
    public Optional<Output<List<MigrationIncludeObjectArgs>>> includeObjects() {
        return Optional.ofNullable(this.includeObjects);
    }

    /**
     * (Updatable) Optional settings for Data Pump Export and Import jobs
     * 
     */
    @Import(name="initialLoadSettings")
    private @Nullable Output<MigrationInitialLoadSettingsArgs> initialLoadSettings;

    /**
     * @return (Updatable) Optional settings for Data Pump Export and Import jobs
     * 
     */
    public Optional<Output<MigrationInitialLoadSettingsArgs>> initialLoadSettings() {
        return Optional.ofNullable(this.initialLoadSettings);
    }

    /**
     * Additional status related to the execution and current state of the Migration.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Additional status related to the execution and current state of the Migration.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) The OCID of the resource being referenced.
     * 
     */
    @Import(name="sourceContainerDatabaseConnectionId")
    private @Nullable Output<String> sourceContainerDatabaseConnectionId;

    /**
     * @return (Updatable) The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> sourceContainerDatabaseConnectionId() {
        return Optional.ofNullable(this.sourceContainerDatabaseConnectionId);
    }

    /**
     * (Updatable) The OCID of the resource being referenced.
     * 
     */
    @Import(name="sourceDatabaseConnectionId")
    private @Nullable Output<String> sourceDatabaseConnectionId;

    /**
     * @return (Updatable) The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> sourceDatabaseConnectionId() {
        return Optional.ofNullable(this.sourceDatabaseConnectionId);
    }

    /**
     * (Updatable) The OCID of the resource being referenced.
     * 
     */
    @Import(name="sourceStandbyDatabaseConnectionId")
    private @Nullable Output<String> sourceStandbyDatabaseConnectionId;

    /**
     * @return (Updatable) The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> sourceStandbyDatabaseConnectionId() {
        return Optional.ofNullable(this.sourceStandbyDatabaseConnectionId);
    }

    /**
     * The current state of the Migration resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Migration resource.
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
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * (Updatable) The OCID of the resource being referenced.
     * 
     */
    @Import(name="targetDatabaseConnectionId")
    private @Nullable Output<String> targetDatabaseConnectionId;

    /**
     * @return (Updatable) The OCID of the resource being referenced.
     * 
     */
    public Optional<Output<String>> targetDatabaseConnectionId() {
        return Optional.ofNullable(this.targetDatabaseConnectionId);
    }

    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    @Import(name="timeLastMigration")
    private @Nullable Output<String> timeLastMigration;

    /**
     * @return An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public Optional<Output<String>> timeLastMigration() {
        return Optional.ofNullable(this.timeLastMigration);
    }

    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * (Updatable) The type of the migration to be performed. Example: ONLINE if no downtime is preferred for a migration. This method uses Oracle GoldenGate for replication.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) The type of the migration to be performed. Example: ONLINE if no downtime is preferred for a migration. This method uses Oracle GoldenGate for replication.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    /**
     * You can optionally pause a migration after a job phase. This property allows you to optionally specify the phase after which you can pause the migration.
     * 
     */
    @Import(name="waitAfter")
    private @Nullable Output<String> waitAfter;

    /**
     * @return You can optionally pause a migration after a job phase. This property allows you to optionally specify the phase after which you can pause the migration.
     * 
     */
    public Optional<Output<String>> waitAfter() {
        return Optional.ofNullable(this.waitAfter);
    }

    private MigrationState() {}

    private MigrationState(MigrationState $) {
        this.advancedParameters = $.advancedParameters;
        this.advisorSettings = $.advisorSettings;
        this.bulkIncludeExcludeData = $.bulkIncludeExcludeData;
        this.compartmentId = $.compartmentId;
        this.dataTransferMediumDetails = $.dataTransferMediumDetails;
        this.databaseCombination = $.databaseCombination;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.excludeObjects = $.excludeObjects;
        this.executingJobId = $.executingJobId;
        this.freeformTags = $.freeformTags;
        this.ggsDetails = $.ggsDetails;
        this.hubDetails = $.hubDetails;
        this.includeObjects = $.includeObjects;
        this.initialLoadSettings = $.initialLoadSettings;
        this.lifecycleDetails = $.lifecycleDetails;
        this.sourceContainerDatabaseConnectionId = $.sourceContainerDatabaseConnectionId;
        this.sourceDatabaseConnectionId = $.sourceDatabaseConnectionId;
        this.sourceStandbyDatabaseConnectionId = $.sourceStandbyDatabaseConnectionId;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.targetDatabaseConnectionId = $.targetDatabaseConnectionId;
        this.timeCreated = $.timeCreated;
        this.timeLastMigration = $.timeLastMigration;
        this.timeUpdated = $.timeUpdated;
        this.type = $.type;
        this.waitAfter = $.waitAfter;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationState $;

        public Builder() {
            $ = new MigrationState();
        }

        public Builder(MigrationState defaults) {
            $ = new MigrationState(Objects.requireNonNull(defaults));
        }

        /**
         * @param advancedParameters (Updatable) List of Migration Parameter objects.
         * 
         * @return builder
         * 
         */
        public Builder advancedParameters(@Nullable Output<List<MigrationAdvancedParameterArgs>> advancedParameters) {
            $.advancedParameters = advancedParameters;
            return this;
        }

        /**
         * @param advancedParameters (Updatable) List of Migration Parameter objects.
         * 
         * @return builder
         * 
         */
        public Builder advancedParameters(List<MigrationAdvancedParameterArgs> advancedParameters) {
            return advancedParameters(Output.of(advancedParameters));
        }

        /**
         * @param advancedParameters (Updatable) List of Migration Parameter objects.
         * 
         * @return builder
         * 
         */
        public Builder advancedParameters(MigrationAdvancedParameterArgs... advancedParameters) {
            return advancedParameters(List.of(advancedParameters));
        }

        /**
         * @param advisorSettings (Updatable) Optional Pre-Migration advisor settings.
         * 
         * @return builder
         * 
         */
        public Builder advisorSettings(@Nullable Output<MigrationAdvisorSettingsArgs> advisorSettings) {
            $.advisorSettings = advisorSettings;
            return this;
        }

        /**
         * @param advisorSettings (Updatable) Optional Pre-Migration advisor settings.
         * 
         * @return builder
         * 
         */
        public Builder advisorSettings(MigrationAdvisorSettingsArgs advisorSettings) {
            return advisorSettings(Output.of(advisorSettings));
        }

        /**
         * @param bulkIncludeExcludeData Specifies the database objects to be excluded from the migration in bulk. The definition accepts input in a CSV format, newline separated for each entry. More details can be found in the documentation.
         * 
         * @return builder
         * 
         */
        public Builder bulkIncludeExcludeData(@Nullable Output<String> bulkIncludeExcludeData) {
            $.bulkIncludeExcludeData = bulkIncludeExcludeData;
            return this;
        }

        /**
         * @param bulkIncludeExcludeData Specifies the database objects to be excluded from the migration in bulk. The definition accepts input in a CSV format, newline separated for each entry. More details can be found in the documentation.
         * 
         * @return builder
         * 
         */
        public Builder bulkIncludeExcludeData(String bulkIncludeExcludeData) {
            return bulkIncludeExcludeData(Output.of(bulkIncludeExcludeData));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dataTransferMediumDetails (Updatable) Optional additional properties for data transfer.
         * 
         * @return builder
         * 
         */
        public Builder dataTransferMediumDetails(@Nullable Output<MigrationDataTransferMediumDetailsArgs> dataTransferMediumDetails) {
            $.dataTransferMediumDetails = dataTransferMediumDetails;
            return this;
        }

        /**
         * @param dataTransferMediumDetails (Updatable) Optional additional properties for data transfer.
         * 
         * @return builder
         * 
         */
        public Builder dataTransferMediumDetails(MigrationDataTransferMediumDetailsArgs dataTransferMediumDetails) {
            return dataTransferMediumDetails(Output.of(dataTransferMediumDetails));
        }

        /**
         * @param databaseCombination (Updatable) The combination of source and target databases participating in a migration. Example: ORACLE means the migration is meant for migrating Oracle source and target databases.
         * 
         * @return builder
         * 
         */
        public Builder databaseCombination(@Nullable Output<String> databaseCombination) {
            $.databaseCombination = databaseCombination;
            return this;
        }

        /**
         * @param databaseCombination (Updatable) The combination of source and target databases participating in a migration. Example: ORACLE means the migration is meant for migrating Oracle source and target databases.
         * 
         * @return builder
         * 
         */
        public Builder databaseCombination(String databaseCombination) {
            return databaseCombination(Output.of(databaseCombination));
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
         * @param description (Updatable) A user-friendly description. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param excludeObjects Database objects to exclude from migration, cannot be specified alongside &#39;includeObjects&#39;
         * 
         * @return builder
         * 
         */
        public Builder excludeObjects(@Nullable Output<List<MigrationExcludeObjectArgs>> excludeObjects) {
            $.excludeObjects = excludeObjects;
            return this;
        }

        /**
         * @param excludeObjects Database objects to exclude from migration, cannot be specified alongside &#39;includeObjects&#39;
         * 
         * @return builder
         * 
         */
        public Builder excludeObjects(List<MigrationExcludeObjectArgs> excludeObjects) {
            return excludeObjects(Output.of(excludeObjects));
        }

        /**
         * @param excludeObjects Database objects to exclude from migration, cannot be specified alongside &#39;includeObjects&#39;
         * 
         * @return builder
         * 
         */
        public Builder excludeObjects(MigrationExcludeObjectArgs... excludeObjects) {
            return excludeObjects(List.of(excludeObjects));
        }

        /**
         * @param executingJobId The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder executingJobId(@Nullable Output<String> executingJobId) {
            $.executingJobId = executingJobId;
            return this;
        }

        /**
         * @param executingJobId The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder executingJobId(String executingJobId) {
            return executingJobId(Output.of(executingJobId));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {&#34;Department&#34;: &#34;Finance&#34;}
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {&#34;Department&#34;: &#34;Finance&#34;}
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param ggsDetails (Updatable) Optional settings for Oracle GoldenGate processes
         * 
         * @return builder
         * 
         */
        public Builder ggsDetails(@Nullable Output<MigrationGgsDetailsArgs> ggsDetails) {
            $.ggsDetails = ggsDetails;
            return this;
        }

        /**
         * @param ggsDetails (Updatable) Optional settings for Oracle GoldenGate processes
         * 
         * @return builder
         * 
         */
        public Builder ggsDetails(MigrationGgsDetailsArgs ggsDetails) {
            return ggsDetails(Output.of(ggsDetails));
        }

        /**
         * @param hubDetails (Updatable) Details about Oracle GoldenGate Microservices.
         * 
         * @return builder
         * 
         */
        public Builder hubDetails(@Nullable Output<MigrationHubDetailsArgs> hubDetails) {
            $.hubDetails = hubDetails;
            return this;
        }

        /**
         * @param hubDetails (Updatable) Details about Oracle GoldenGate Microservices.
         * 
         * @return builder
         * 
         */
        public Builder hubDetails(MigrationHubDetailsArgs hubDetails) {
            return hubDetails(Output.of(hubDetails));
        }

        /**
         * @param includeObjects Database objects to include from migration, cannot be specified alongside &#39;excludeObjects&#39;
         * 
         * @return builder
         * 
         */
        public Builder includeObjects(@Nullable Output<List<MigrationIncludeObjectArgs>> includeObjects) {
            $.includeObjects = includeObjects;
            return this;
        }

        /**
         * @param includeObjects Database objects to include from migration, cannot be specified alongside &#39;excludeObjects&#39;
         * 
         * @return builder
         * 
         */
        public Builder includeObjects(List<MigrationIncludeObjectArgs> includeObjects) {
            return includeObjects(Output.of(includeObjects));
        }

        /**
         * @param includeObjects Database objects to include from migration, cannot be specified alongside &#39;excludeObjects&#39;
         * 
         * @return builder
         * 
         */
        public Builder includeObjects(MigrationIncludeObjectArgs... includeObjects) {
            return includeObjects(List.of(includeObjects));
        }

        /**
         * @param initialLoadSettings (Updatable) Optional settings for Data Pump Export and Import jobs
         * 
         * @return builder
         * 
         */
        public Builder initialLoadSettings(@Nullable Output<MigrationInitialLoadSettingsArgs> initialLoadSettings) {
            $.initialLoadSettings = initialLoadSettings;
            return this;
        }

        /**
         * @param initialLoadSettings (Updatable) Optional settings for Data Pump Export and Import jobs
         * 
         * @return builder
         * 
         */
        public Builder initialLoadSettings(MigrationInitialLoadSettingsArgs initialLoadSettings) {
            return initialLoadSettings(Output.of(initialLoadSettings));
        }

        /**
         * @param lifecycleDetails Additional status related to the execution and current state of the Migration.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Additional status related to the execution and current state of the Migration.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param sourceContainerDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder sourceContainerDatabaseConnectionId(@Nullable Output<String> sourceContainerDatabaseConnectionId) {
            $.sourceContainerDatabaseConnectionId = sourceContainerDatabaseConnectionId;
            return this;
        }

        /**
         * @param sourceContainerDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder sourceContainerDatabaseConnectionId(String sourceContainerDatabaseConnectionId) {
            return sourceContainerDatabaseConnectionId(Output.of(sourceContainerDatabaseConnectionId));
        }

        /**
         * @param sourceDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder sourceDatabaseConnectionId(@Nullable Output<String> sourceDatabaseConnectionId) {
            $.sourceDatabaseConnectionId = sourceDatabaseConnectionId;
            return this;
        }

        /**
         * @param sourceDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder sourceDatabaseConnectionId(String sourceDatabaseConnectionId) {
            return sourceDatabaseConnectionId(Output.of(sourceDatabaseConnectionId));
        }

        /**
         * @param sourceStandbyDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder sourceStandbyDatabaseConnectionId(@Nullable Output<String> sourceStandbyDatabaseConnectionId) {
            $.sourceStandbyDatabaseConnectionId = sourceStandbyDatabaseConnectionId;
            return this;
        }

        /**
         * @param sourceStandbyDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder sourceStandbyDatabaseConnectionId(String sourceStandbyDatabaseConnectionId) {
            return sourceStandbyDatabaseConnectionId(Output.of(sourceStandbyDatabaseConnectionId));
        }

        /**
         * @param state The current state of the Migration resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Migration resource.
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
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param targetDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder targetDatabaseConnectionId(@Nullable Output<String> targetDatabaseConnectionId) {
            $.targetDatabaseConnectionId = targetDatabaseConnectionId;
            return this;
        }

        /**
         * @param targetDatabaseConnectionId (Updatable) The OCID of the resource being referenced.
         * 
         * @return builder
         * 
         */
        public Builder targetDatabaseConnectionId(String targetDatabaseConnectionId) {
            return targetDatabaseConnectionId(Output.of(targetDatabaseConnectionId));
        }

        /**
         * @param timeCreated An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeLastMigration An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
         * 
         * @return builder
         * 
         */
        public Builder timeLastMigration(@Nullable Output<String> timeLastMigration) {
            $.timeLastMigration = timeLastMigration;
            return this;
        }

        /**
         * @param timeLastMigration An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
         * 
         * @return builder
         * 
         */
        public Builder timeLastMigration(String timeLastMigration) {
            return timeLastMigration(Output.of(timeLastMigration));
        }

        /**
         * @param timeUpdated An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param type (Updatable) The type of the migration to be performed. Example: ONLINE if no downtime is preferred for a migration. This method uses Oracle GoldenGate for replication.
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
         * @param type (Updatable) The type of the migration to be performed. Example: ONLINE if no downtime is preferred for a migration. This method uses Oracle GoldenGate for replication.
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

        /**
         * @param waitAfter You can optionally pause a migration after a job phase. This property allows you to optionally specify the phase after which you can pause the migration.
         * 
         * @return builder
         * 
         */
        public Builder waitAfter(@Nullable Output<String> waitAfter) {
            $.waitAfter = waitAfter;
            return this;
        }

        /**
         * @param waitAfter You can optionally pause a migration after a job phase. This property allows you to optionally specify the phase after which you can pause the migration.
         * 
         * @return builder
         * 
         */
        public Builder waitAfter(String waitAfter) {
            return waitAfter(Output.of(waitAfter));
        }

        public MigrationState build() {
            return $;
        }
    }

}
