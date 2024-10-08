// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalExadataInfrastructureDatabaseSystemArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalExadataInfrastructureStorageGridArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalExadataInfrastructureState extends com.pulumi.resources.ResourceArgs {

    public static final ExternalExadataInfrastructureState Empty = new ExternalExadataInfrastructureState();

    /**
     * The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="additionalDetails")
    private @Nullable Output<Map<String,String>> additionalDetails;

    /**
     * @return The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> additionalDetails() {
        return Optional.ofNullable(this.additionalDetails);
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
     * The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
     * 
     */
    @Import(name="databaseCompartments")
    private @Nullable Output<List<String>> databaseCompartments;

    /**
     * @return The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
     * 
     */
    public Optional<Output<List<String>>> databaseCompartments() {
        return Optional.ofNullable(this.databaseCompartments);
    }

    /**
     * A list of DB systems.
     * 
     */
    @Import(name="databaseSystems")
    private @Nullable Output<List<ExternalExadataInfrastructureDatabaseSystemArgs>> databaseSystems;

    /**
     * @return A list of DB systems.
     * 
     */
    public Optional<Output<List<ExternalExadataInfrastructureDatabaseSystemArgs>>> databaseSystems() {
        return Optional.ofNullable(this.databaseSystems);
    }

    /**
     * (Updatable) The list of DB systems in the Exadata infrastructure.
     * 
     */
    @Import(name="dbSystemIds")
    private @Nullable Output<List<String>> dbSystemIds;

    /**
     * @return (Updatable) The list of DB systems in the Exadata infrastructure.
     * 
     */
    public Optional<Output<List<String>>> dbSystemIds() {
        return Optional.ofNullable(this.dbSystemIds);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The unique key of the discovery request.
     * 
     */
    @Import(name="discoveryKey")
    private @Nullable Output<String> discoveryKey;

    /**
     * @return (Updatable) The unique key of the discovery request.
     * 
     */
    public Optional<Output<String>> discoveryKey() {
        return Optional.ofNullable(this.discoveryKey);
    }

    /**
     * (Updatable) The name of the Exadata infrastructure.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The name of the Exadata infrastructure.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The internal ID of the Exadata resource.
     * 
     */
    @Import(name="internalId")
    private @Nullable Output<String> internalId;

    /**
     * @return The internal ID of the Exadata resource.
     * 
     */
    public Optional<Output<String>> internalId() {
        return Optional.ofNullable(this.internalId);
    }

    /**
     * (Updatable) The Oracle license model that applies to the database management resources.
     * 
     */
    @Import(name="licenseModel")
    private @Nullable Output<String> licenseModel;

    /**
     * @return (Updatable) The Oracle license model that applies to the database management resources.
     * 
     */
    public Optional<Output<String>> licenseModel() {
        return Optional.ofNullable(this.licenseModel);
    }

    /**
     * The details of the lifecycle state of the Exadata resource.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return The details of the lifecycle state of the Exadata resource.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The rack size of the Exadata infrastructure.
     * 
     */
    @Import(name="rackSize")
    private @Nullable Output<String> rackSize;

    /**
     * @return The rack size of the Exadata infrastructure.
     * 
     */
    public Optional<Output<String>> rackSize() {
        return Optional.ofNullable(this.rackSize);
    }

    /**
     * The current lifecycle state of the database resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the database resource.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The status of the Exadata resource.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return The status of the Exadata resource.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * The Exadata storage server grid of the Exadata infrastructure.
     * 
     */
    @Import(name="storageGrids")
    private @Nullable Output<List<ExternalExadataInfrastructureStorageGridArgs>> storageGrids;

    /**
     * @return The Exadata storage server grid of the Exadata infrastructure.
     * 
     */
    public Optional<Output<List<ExternalExadataInfrastructureStorageGridArgs>>> storageGrids() {
        return Optional.ofNullable(this.storageGrids);
    }

    /**
     * (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="storageServerNames")
    private @Nullable Output<List<String>> storageServerNames;

    /**
     * @return (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<List<String>>> storageServerNames() {
        return Optional.ofNullable(this.storageServerNames);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The timestamp of the creation of the Exadata resource.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The timestamp of the creation of the Exadata resource.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The timestamp of the last update of the Exadata resource.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The timestamp of the last update of the Exadata resource.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The version of the Exadata resource.
     * 
     */
    @Import(name="version")
    private @Nullable Output<String> version;

    /**
     * @return The version of the Exadata resource.
     * 
     */
    public Optional<Output<String>> version() {
        return Optional.ofNullable(this.version);
    }

    private ExternalExadataInfrastructureState() {}

    private ExternalExadataInfrastructureState(ExternalExadataInfrastructureState $) {
        this.additionalDetails = $.additionalDetails;
        this.compartmentId = $.compartmentId;
        this.databaseCompartments = $.databaseCompartments;
        this.databaseSystems = $.databaseSystems;
        this.dbSystemIds = $.dbSystemIds;
        this.definedTags = $.definedTags;
        this.discoveryKey = $.discoveryKey;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.internalId = $.internalId;
        this.licenseModel = $.licenseModel;
        this.lifecycleDetails = $.lifecycleDetails;
        this.rackSize = $.rackSize;
        this.state = $.state;
        this.status = $.status;
        this.storageGrids = $.storageGrids;
        this.storageServerNames = $.storageServerNames;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.version = $.version;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalExadataInfrastructureState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalExadataInfrastructureState $;

        public Builder() {
            $ = new ExternalExadataInfrastructureState();
        }

        public Builder(ExternalExadataInfrastructureState defaults) {
            $ = new ExternalExadataInfrastructureState(Objects.requireNonNull(defaults));
        }

        /**
         * @param additionalDetails The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder additionalDetails(@Nullable Output<Map<String,String>> additionalDetails) {
            $.additionalDetails = additionalDetails;
            return this;
        }

        /**
         * @param additionalDetails The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder additionalDetails(Map<String,String> additionalDetails) {
            return additionalDetails(Output.of(additionalDetails));
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
         * @param databaseCompartments The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
         * 
         * @return builder
         * 
         */
        public Builder databaseCompartments(@Nullable Output<List<String>> databaseCompartments) {
            $.databaseCompartments = databaseCompartments;
            return this;
        }

        /**
         * @param databaseCompartments The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
         * 
         * @return builder
         * 
         */
        public Builder databaseCompartments(List<String> databaseCompartments) {
            return databaseCompartments(Output.of(databaseCompartments));
        }

        /**
         * @param databaseCompartments The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
         * 
         * @return builder
         * 
         */
        public Builder databaseCompartments(String... databaseCompartments) {
            return databaseCompartments(List.of(databaseCompartments));
        }

        /**
         * @param databaseSystems A list of DB systems.
         * 
         * @return builder
         * 
         */
        public Builder databaseSystems(@Nullable Output<List<ExternalExadataInfrastructureDatabaseSystemArgs>> databaseSystems) {
            $.databaseSystems = databaseSystems;
            return this;
        }

        /**
         * @param databaseSystems A list of DB systems.
         * 
         * @return builder
         * 
         */
        public Builder databaseSystems(List<ExternalExadataInfrastructureDatabaseSystemArgs> databaseSystems) {
            return databaseSystems(Output.of(databaseSystems));
        }

        /**
         * @param databaseSystems A list of DB systems.
         * 
         * @return builder
         * 
         */
        public Builder databaseSystems(ExternalExadataInfrastructureDatabaseSystemArgs... databaseSystems) {
            return databaseSystems(List.of(databaseSystems));
        }

        /**
         * @param dbSystemIds (Updatable) The list of DB systems in the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemIds(@Nullable Output<List<String>> dbSystemIds) {
            $.dbSystemIds = dbSystemIds;
            return this;
        }

        /**
         * @param dbSystemIds (Updatable) The list of DB systems in the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemIds(List<String> dbSystemIds) {
            return dbSystemIds(Output.of(dbSystemIds));
        }

        /**
         * @param dbSystemIds (Updatable) The list of DB systems in the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemIds(String... dbSystemIds) {
            return dbSystemIds(List.of(dbSystemIds));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param discoveryKey (Updatable) The unique key of the discovery request.
         * 
         * @return builder
         * 
         */
        public Builder discoveryKey(@Nullable Output<String> discoveryKey) {
            $.discoveryKey = discoveryKey;
            return this;
        }

        /**
         * @param discoveryKey (Updatable) The unique key of the discovery request.
         * 
         * @return builder
         * 
         */
        public Builder discoveryKey(String discoveryKey) {
            return discoveryKey(Output.of(discoveryKey));
        }

        /**
         * @param displayName (Updatable) The name of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The name of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param internalId The internal ID of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder internalId(@Nullable Output<String> internalId) {
            $.internalId = internalId;
            return this;
        }

        /**
         * @param internalId The internal ID of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder internalId(String internalId) {
            return internalId(Output.of(internalId));
        }

        /**
         * @param licenseModel (Updatable) The Oracle license model that applies to the database management resources.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(@Nullable Output<String> licenseModel) {
            $.licenseModel = licenseModel;
            return this;
        }

        /**
         * @param licenseModel (Updatable) The Oracle license model that applies to the database management resources.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(String licenseModel) {
            return licenseModel(Output.of(licenseModel));
        }

        /**
         * @param lifecycleDetails The details of the lifecycle state of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails The details of the lifecycle state of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param rackSize The rack size of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder rackSize(@Nullable Output<String> rackSize) {
            $.rackSize = rackSize;
            return this;
        }

        /**
         * @param rackSize The rack size of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder rackSize(String rackSize) {
            return rackSize(Output.of(rackSize));
        }

        /**
         * @param state The current lifecycle state of the database resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the database resource.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param status The status of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status The status of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param storageGrids The Exadata storage server grid of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder storageGrids(@Nullable Output<List<ExternalExadataInfrastructureStorageGridArgs>> storageGrids) {
            $.storageGrids = storageGrids;
            return this;
        }

        /**
         * @param storageGrids The Exadata storage server grid of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder storageGrids(List<ExternalExadataInfrastructureStorageGridArgs> storageGrids) {
            return storageGrids(Output.of(storageGrids));
        }

        /**
         * @param storageGrids The Exadata storage server grid of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder storageGrids(ExternalExadataInfrastructureStorageGridArgs... storageGrids) {
            return storageGrids(List.of(storageGrids));
        }

        /**
         * @param storageServerNames (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder storageServerNames(@Nullable Output<List<String>> storageServerNames) {
            $.storageServerNames = storageServerNames;
            return this;
        }

        /**
         * @param storageServerNames (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder storageServerNames(List<String> storageServerNames) {
            return storageServerNames(Output.of(storageServerNames));
        }

        /**
         * @param storageServerNames (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder storageServerNames(String... storageServerNames) {
            return storageServerNames(List.of(storageServerNames));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The timestamp of the creation of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The timestamp of the creation of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The timestamp of the last update of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The timestamp of the last update of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param version The version of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder version(@Nullable Output<String> version) {
            $.version = version;
            return this;
        }

        /**
         * @param version The version of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder version(String version) {
            return version(Output.of(version));
        }

        public ExternalExadataInfrastructureState build() {
            return $;
        }
    }

}
