// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceApplicationScheduleFrequencyDetailsArgs;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceApplicationScheduleMetadataArgs;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceApplicationScheduleParentRefArgs;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceApplicationScheduleRegistryMetadataArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceApplicationScheduleState extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceApplicationScheduleState Empty = new WorkspaceApplicationScheduleState();

    /**
     * The application key.
     * 
     */
    @Import(name="applicationKey")
    private @Nullable Output<String> applicationKey;

    /**
     * @return The application key.
     * 
     */
    public Optional<Output<String>> applicationKey() {
        return Optional.ofNullable(this.applicationKey);
    }

    /**
     * (Updatable) Detailed description for the object.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Detailed description for the object.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The model that holds the frequency details.
     * 
     */
    @Import(name="frequencyDetails")
    private @Nullable Output<WorkspaceApplicationScheduleFrequencyDetailsArgs> frequencyDetails;

    /**
     * @return (Updatable) The model that holds the frequency details.
     * 
     */
    public Optional<Output<WorkspaceApplicationScheduleFrequencyDetailsArgs>> frequencyDetails() {
        return Optional.ofNullable(this.frequencyDetails);
    }

    /**
     * (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    @Import(name="identifier")
    private @Nullable Output<String> identifier;

    /**
     * @return (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    public Optional<Output<String>> identifier() {
        return Optional.ofNullable(this.identifier);
    }

    /**
     * (Updatable) A flag to indicate whether daylight adjustment should be considered or not.
     * 
     */
    @Import(name="isDaylightAdjustmentEnabled")
    private @Nullable Output<Boolean> isDaylightAdjustmentEnabled;

    /**
     * @return (Updatable) A flag to indicate whether daylight adjustment should be considered or not.
     * 
     */
    public Optional<Output<Boolean>> isDaylightAdjustmentEnabled() {
        return Optional.ofNullable(this.isDaylightAdjustmentEnabled);
    }

    /**
     * (Updatable) Generated key that can be used in API calls to identify schedule. On scenarios where reference to the schedule is needed, a value can be passed in create.
     * 
     */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return (Updatable) Generated key that can be used in API calls to identify schedule. On scenarios where reference to the schedule is needed, a value can be passed in create.
     * 
     */
    public Optional<Output<String>> key() {
        return Optional.ofNullable(this.key);
    }

    /**
     * A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    @Import(name="metadatas")
    private @Nullable Output<List<WorkspaceApplicationScheduleMetadataArgs>> metadatas;

    /**
     * @return A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    public Optional<Output<List<WorkspaceApplicationScheduleMetadataArgs>>> metadatas() {
        return Optional.ofNullable(this.metadatas);
    }

    /**
     * The type of the object.
     * 
     */
    @Import(name="modelType")
    private @Nullable Output<String> modelType;

    /**
     * @return The type of the object.
     * 
     */
    public Optional<Output<String>> modelType() {
        return Optional.ofNullable(this.modelType);
    }

    /**
     * (Updatable) This is a version number that is used by the service to upgrade objects if needed through releases of the service.
     * 
     */
    @Import(name="modelVersion")
    private @Nullable Output<String> modelVersion;

    /**
     * @return (Updatable) This is a version number that is used by the service to upgrade objects if needed through releases of the service.
     * 
     */
    public Optional<Output<String>> modelVersion() {
        return Optional.ofNullable(this.modelVersion);
    }

    /**
     * (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    @Import(name="objectStatus")
    private @Nullable Output<Integer> objectStatus;

    /**
     * @return (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    public Optional<Output<Integer>> objectStatus() {
        return Optional.ofNullable(this.objectStatus);
    }

    /**
     * (Updatable) This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
     * 
     */
    @Import(name="objectVersion")
    private @Nullable Output<Integer> objectVersion;

    /**
     * @return (Updatable) This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
     * 
     */
    public Optional<Output<Integer>> objectVersion() {
        return Optional.ofNullable(this.objectVersion);
    }

    /**
     * A reference to the object&#39;s parent.
     * 
     */
    @Import(name="parentReves")
    private @Nullable Output<List<WorkspaceApplicationScheduleParentRefArgs>> parentReves;

    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    public Optional<Output<List<WorkspaceApplicationScheduleParentRefArgs>>> parentReves() {
        return Optional.ofNullable(this.parentReves);
    }

    /**
     * (Updatable) Information about the object and its parent.
     * 
     */
    @Import(name="registryMetadata")
    private @Nullable Output<WorkspaceApplicationScheduleRegistryMetadataArgs> registryMetadata;

    /**
     * @return (Updatable) Information about the object and its parent.
     * 
     */
    public Optional<Output<WorkspaceApplicationScheduleRegistryMetadataArgs>> registryMetadata() {
        return Optional.ofNullable(this.registryMetadata);
    }

    /**
     * (Updatable) The timezone for the schedule.
     * 
     */
    @Import(name="timezone")
    private @Nullable Output<String> timezone;

    /**
     * @return (Updatable) The timezone for the schedule.
     * 
     */
    public Optional<Output<String>> timezone() {
        return Optional.ofNullable(this.timezone);
    }

    /**
     * The workspace ID.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="workspaceId")
    private @Nullable Output<String> workspaceId;

    /**
     * @return The workspace ID.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> workspaceId() {
        return Optional.ofNullable(this.workspaceId);
    }

    private WorkspaceApplicationScheduleState() {}

    private WorkspaceApplicationScheduleState(WorkspaceApplicationScheduleState $) {
        this.applicationKey = $.applicationKey;
        this.description = $.description;
        this.frequencyDetails = $.frequencyDetails;
        this.identifier = $.identifier;
        this.isDaylightAdjustmentEnabled = $.isDaylightAdjustmentEnabled;
        this.key = $.key;
        this.metadatas = $.metadatas;
        this.modelType = $.modelType;
        this.modelVersion = $.modelVersion;
        this.name = $.name;
        this.objectStatus = $.objectStatus;
        this.objectVersion = $.objectVersion;
        this.parentReves = $.parentReves;
        this.registryMetadata = $.registryMetadata;
        this.timezone = $.timezone;
        this.workspaceId = $.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceApplicationScheduleState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceApplicationScheduleState $;

        public Builder() {
            $ = new WorkspaceApplicationScheduleState();
        }

        public Builder(WorkspaceApplicationScheduleState defaults) {
            $ = new WorkspaceApplicationScheduleState(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationKey The application key.
         * 
         * @return builder
         * 
         */
        public Builder applicationKey(@Nullable Output<String> applicationKey) {
            $.applicationKey = applicationKey;
            return this;
        }

        /**
         * @param applicationKey The application key.
         * 
         * @return builder
         * 
         */
        public Builder applicationKey(String applicationKey) {
            return applicationKey(Output.of(applicationKey));
        }

        /**
         * @param description (Updatable) Detailed description for the object.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Detailed description for the object.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param frequencyDetails (Updatable) The model that holds the frequency details.
         * 
         * @return builder
         * 
         */
        public Builder frequencyDetails(@Nullable Output<WorkspaceApplicationScheduleFrequencyDetailsArgs> frequencyDetails) {
            $.frequencyDetails = frequencyDetails;
            return this;
        }

        /**
         * @param frequencyDetails (Updatable) The model that holds the frequency details.
         * 
         * @return builder
         * 
         */
        public Builder frequencyDetails(WorkspaceApplicationScheduleFrequencyDetailsArgs frequencyDetails) {
            return frequencyDetails(Output.of(frequencyDetails));
        }

        /**
         * @param identifier (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
         * 
         * @return builder
         * 
         */
        public Builder identifier(@Nullable Output<String> identifier) {
            $.identifier = identifier;
            return this;
        }

        /**
         * @param identifier (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
         * 
         * @return builder
         * 
         */
        public Builder identifier(String identifier) {
            return identifier(Output.of(identifier));
        }

        /**
         * @param isDaylightAdjustmentEnabled (Updatable) A flag to indicate whether daylight adjustment should be considered or not.
         * 
         * @return builder
         * 
         */
        public Builder isDaylightAdjustmentEnabled(@Nullable Output<Boolean> isDaylightAdjustmentEnabled) {
            $.isDaylightAdjustmentEnabled = isDaylightAdjustmentEnabled;
            return this;
        }

        /**
         * @param isDaylightAdjustmentEnabled (Updatable) A flag to indicate whether daylight adjustment should be considered or not.
         * 
         * @return builder
         * 
         */
        public Builder isDaylightAdjustmentEnabled(Boolean isDaylightAdjustmentEnabled) {
            return isDaylightAdjustmentEnabled(Output.of(isDaylightAdjustmentEnabled));
        }

        /**
         * @param key (Updatable) Generated key that can be used in API calls to identify schedule. On scenarios where reference to the schedule is needed, a value can be passed in create.
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key (Updatable) Generated key that can be used in API calls to identify schedule. On scenarios where reference to the schedule is needed, a value can be passed in create.
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param metadatas A summary type containing information about the object including its key, name and when/who created/updated it.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(@Nullable Output<List<WorkspaceApplicationScheduleMetadataArgs>> metadatas) {
            $.metadatas = metadatas;
            return this;
        }

        /**
         * @param metadatas A summary type containing information about the object including its key, name and when/who created/updated it.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(List<WorkspaceApplicationScheduleMetadataArgs> metadatas) {
            return metadatas(Output.of(metadatas));
        }

        /**
         * @param metadatas A summary type containing information about the object including its key, name and when/who created/updated it.
         * 
         * @return builder
         * 
         */
        public Builder metadatas(WorkspaceApplicationScheduleMetadataArgs... metadatas) {
            return metadatas(List.of(metadatas));
        }

        /**
         * @param modelType The type of the object.
         * 
         * @return builder
         * 
         */
        public Builder modelType(@Nullable Output<String> modelType) {
            $.modelType = modelType;
            return this;
        }

        /**
         * @param modelType The type of the object.
         * 
         * @return builder
         * 
         */
        public Builder modelType(String modelType) {
            return modelType(Output.of(modelType));
        }

        /**
         * @param modelVersion (Updatable) This is a version number that is used by the service to upgrade objects if needed through releases of the service.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(@Nullable Output<String> modelVersion) {
            $.modelVersion = modelVersion;
            return this;
        }

        /**
         * @param modelVersion (Updatable) This is a version number that is used by the service to upgrade objects if needed through releases of the service.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(String modelVersion) {
            return modelVersion(Output.of(modelVersion));
        }

        /**
         * @param name (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param objectStatus (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
         * 
         * @return builder
         * 
         */
        public Builder objectStatus(@Nullable Output<Integer> objectStatus) {
            $.objectStatus = objectStatus;
            return this;
        }

        /**
         * @param objectStatus (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
         * 
         * @return builder
         * 
         */
        public Builder objectStatus(Integer objectStatus) {
            return objectStatus(Output.of(objectStatus));
        }

        /**
         * @param objectVersion (Updatable) This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
         * 
         * @return builder
         * 
         */
        public Builder objectVersion(@Nullable Output<Integer> objectVersion) {
            $.objectVersion = objectVersion;
            return this;
        }

        /**
         * @param objectVersion (Updatable) This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
         * 
         * @return builder
         * 
         */
        public Builder objectVersion(Integer objectVersion) {
            return objectVersion(Output.of(objectVersion));
        }

        /**
         * @param parentReves A reference to the object&#39;s parent.
         * 
         * @return builder
         * 
         */
        public Builder parentReves(@Nullable Output<List<WorkspaceApplicationScheduleParentRefArgs>> parentReves) {
            $.parentReves = parentReves;
            return this;
        }

        /**
         * @param parentReves A reference to the object&#39;s parent.
         * 
         * @return builder
         * 
         */
        public Builder parentReves(List<WorkspaceApplicationScheduleParentRefArgs> parentReves) {
            return parentReves(Output.of(parentReves));
        }

        /**
         * @param parentReves A reference to the object&#39;s parent.
         * 
         * @return builder
         * 
         */
        public Builder parentReves(WorkspaceApplicationScheduleParentRefArgs... parentReves) {
            return parentReves(List.of(parentReves));
        }

        /**
         * @param registryMetadata (Updatable) Information about the object and its parent.
         * 
         * @return builder
         * 
         */
        public Builder registryMetadata(@Nullable Output<WorkspaceApplicationScheduleRegistryMetadataArgs> registryMetadata) {
            $.registryMetadata = registryMetadata;
            return this;
        }

        /**
         * @param registryMetadata (Updatable) Information about the object and its parent.
         * 
         * @return builder
         * 
         */
        public Builder registryMetadata(WorkspaceApplicationScheduleRegistryMetadataArgs registryMetadata) {
            return registryMetadata(Output.of(registryMetadata));
        }

        /**
         * @param timezone (Updatable) The timezone for the schedule.
         * 
         * @return builder
         * 
         */
        public Builder timezone(@Nullable Output<String> timezone) {
            $.timezone = timezone;
            return this;
        }

        /**
         * @param timezone (Updatable) The timezone for the schedule.
         * 
         * @return builder
         * 
         */
        public Builder timezone(String timezone) {
            return timezone(Output.of(timezone));
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(@Nullable Output<String> workspaceId) {
            $.workspaceId = workspaceId;
            return this;
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(String workspaceId) {
            return workspaceId(Output.of(workspaceId));
        }

        public WorkspaceApplicationScheduleState build() {
            return $;
        }
    }

}
