// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceExportRequestExportedItemArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceExportRequestState extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceExportRequestState Empty = new WorkspaceExportRequestState();

    /**
     * This field controls if the references will be exported along with the objects
     * 
     */
    @Import(name="areReferencesIncluded")
    private @Nullable Output<Boolean> areReferencesIncluded;

    /**
     * @return This field controls if the references will be exported along with the objects
     * 
     */
    public Optional<Output<Boolean>> areReferencesIncluded() {
        return Optional.ofNullable(this.areReferencesIncluded);
    }

    /**
     * Name of the Object Storage bucket where the object will be exported.
     * 
     */
    @Import(name="bucket")
    private @Nullable Output<String> bucket;

    /**
     * @return Name of the Object Storage bucket where the object will be exported.
     * 
     */
    public Optional<Output<String>> bucket() {
        return Optional.ofNullable(this.bucket);
    }

    /**
     * Name of the user who initiated export request.
     * 
     */
    @Import(name="createdBy")
    private @Nullable Output<String> createdBy;

    /**
     * @return Name of the user who initiated export request.
     * 
     */
    public Optional<Output<String>> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }

    /**
     * Contains key of the error
     * 
     */
    @Import(name="errorMessages")
    private @Nullable Output<Map<String,Object>> errorMessages;

    /**
     * @return Contains key of the error
     * 
     */
    public Optional<Output<Map<String,Object>>> errorMessages() {
        return Optional.ofNullable(this.errorMessages);
    }

    /**
     * The array of exported object details.
     * 
     */
    @Import(name="exportedItems")
    private @Nullable Output<List<WorkspaceExportRequestExportedItemArgs>> exportedItems;

    /**
     * @return The array of exported object details.
     * 
     */
    public Optional<Output<List<WorkspaceExportRequestExportedItemArgs>>> exportedItems() {
        return Optional.ofNullable(this.exportedItems);
    }

    /**
     * Name of the exported zip file.
     * 
     */
    @Import(name="fileName")
    private @Nullable Output<String> fileName;

    /**
     * @return Name of the exported zip file.
     * 
     */
    public Optional<Output<String>> fileName() {
        return Optional.ofNullable(this.fileName);
    }

    /**
     * Filters for exported objects
     * 
     */
    @Import(name="filters")
    private @Nullable Output<List<String>> filters;

    /**
     * @return Filters for exported objects
     * 
     */
    public Optional<Output<List<String>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Flag to control whether to overwrite the object if it is already present at the provided object storage location.
     * 
     */
    @Import(name="isObjectOverwriteEnabled")
    private @Nullable Output<Boolean> isObjectOverwriteEnabled;

    /**
     * @return Flag to control whether to overwrite the object if it is already present at the provided object storage location.
     * 
     */
    public Optional<Output<Boolean>> isObjectOverwriteEnabled() {
        return Optional.ofNullable(this.isObjectOverwriteEnabled);
    }

    /**
     * Export object request key
     * 
     */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return Export object request key
     * 
     */
    public Optional<Output<String>> key() {
        return Optional.ofNullable(this.key);
    }

    /**
     * Name of the export request.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Name of the export request.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Field is used to specify which object keys to export
     * 
     */
    @Import(name="objectKeys")
    private @Nullable Output<List<String>> objectKeys;

    /**
     * @return Field is used to specify which object keys to export
     * 
     */
    public Optional<Output<List<String>>> objectKeys() {
        return Optional.ofNullable(this.objectKeys);
    }

    /**
     * Region of the object storage (if using object storage of different region)
     * 
     */
    @Import(name="objectStorageRegion")
    private @Nullable Output<String> objectStorageRegion;

    /**
     * @return Region of the object storage (if using object storage of different region)
     * 
     */
    public Optional<Output<String>> objectStorageRegion() {
        return Optional.ofNullable(this.objectStorageRegion);
    }

    /**
     * Optional parameter to point to object storage tenancy (if using Object Storage of different tenancy)
     * 
     */
    @Import(name="objectStorageTenancyId")
    private @Nullable Output<String> objectStorageTenancyId;

    /**
     * @return Optional parameter to point to object storage tenancy (if using Object Storage of different tenancy)
     * 
     */
    public Optional<Output<String>> objectStorageTenancyId() {
        return Optional.ofNullable(this.objectStorageTenancyId);
    }

    /**
     * The array of exported referenced objects.
     * 
     */
    @Import(name="referencedItems")
    private @Nullable Output<String> referencedItems;

    /**
     * @return The array of exported referenced objects.
     * 
     */
    public Optional<Output<String>> referencedItems() {
        return Optional.ofNullable(this.referencedItems);
    }

    /**
     * Export Objects request status.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return Export Objects request status.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * Time at which the request was completely processed.
     * 
     */
    @Import(name="timeEndedInMillis")
    private @Nullable Output<String> timeEndedInMillis;

    /**
     * @return Time at which the request was completely processed.
     * 
     */
    public Optional<Output<String>> timeEndedInMillis() {
        return Optional.ofNullable(this.timeEndedInMillis);
    }

    /**
     * Time at which the request started getting processed.
     * 
     */
    @Import(name="timeStartedInMillis")
    private @Nullable Output<String> timeStartedInMillis;

    /**
     * @return Time at which the request started getting processed.
     * 
     */
    public Optional<Output<String>> timeStartedInMillis() {
        return Optional.ofNullable(this.timeStartedInMillis);
    }

    /**
     * Number of objects that are exported.
     * 
     */
    @Import(name="totalExportedObjectCount")
    private @Nullable Output<Integer> totalExportedObjectCount;

    /**
     * @return Number of objects that are exported.
     * 
     */
    public Optional<Output<Integer>> totalExportedObjectCount() {
        return Optional.ofNullable(this.totalExportedObjectCount);
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

    private WorkspaceExportRequestState() {}

    private WorkspaceExportRequestState(WorkspaceExportRequestState $) {
        this.areReferencesIncluded = $.areReferencesIncluded;
        this.bucket = $.bucket;
        this.createdBy = $.createdBy;
        this.errorMessages = $.errorMessages;
        this.exportedItems = $.exportedItems;
        this.fileName = $.fileName;
        this.filters = $.filters;
        this.isObjectOverwriteEnabled = $.isObjectOverwriteEnabled;
        this.key = $.key;
        this.name = $.name;
        this.objectKeys = $.objectKeys;
        this.objectStorageRegion = $.objectStorageRegion;
        this.objectStorageTenancyId = $.objectStorageTenancyId;
        this.referencedItems = $.referencedItems;
        this.status = $.status;
        this.timeEndedInMillis = $.timeEndedInMillis;
        this.timeStartedInMillis = $.timeStartedInMillis;
        this.totalExportedObjectCount = $.totalExportedObjectCount;
        this.workspaceId = $.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceExportRequestState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceExportRequestState $;

        public Builder() {
            $ = new WorkspaceExportRequestState();
        }

        public Builder(WorkspaceExportRequestState defaults) {
            $ = new WorkspaceExportRequestState(Objects.requireNonNull(defaults));
        }

        /**
         * @param areReferencesIncluded This field controls if the references will be exported along with the objects
         * 
         * @return builder
         * 
         */
        public Builder areReferencesIncluded(@Nullable Output<Boolean> areReferencesIncluded) {
            $.areReferencesIncluded = areReferencesIncluded;
            return this;
        }

        /**
         * @param areReferencesIncluded This field controls if the references will be exported along with the objects
         * 
         * @return builder
         * 
         */
        public Builder areReferencesIncluded(Boolean areReferencesIncluded) {
            return areReferencesIncluded(Output.of(areReferencesIncluded));
        }

        /**
         * @param bucket Name of the Object Storage bucket where the object will be exported.
         * 
         * @return builder
         * 
         */
        public Builder bucket(@Nullable Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket Name of the Object Storage bucket where the object will be exported.
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param createdBy Name of the user who initiated export request.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(@Nullable Output<String> createdBy) {
            $.createdBy = createdBy;
            return this;
        }

        /**
         * @param createdBy Name of the user who initiated export request.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(String createdBy) {
            return createdBy(Output.of(createdBy));
        }

        /**
         * @param errorMessages Contains key of the error
         * 
         * @return builder
         * 
         */
        public Builder errorMessages(@Nullable Output<Map<String,Object>> errorMessages) {
            $.errorMessages = errorMessages;
            return this;
        }

        /**
         * @param errorMessages Contains key of the error
         * 
         * @return builder
         * 
         */
        public Builder errorMessages(Map<String,Object> errorMessages) {
            return errorMessages(Output.of(errorMessages));
        }

        /**
         * @param exportedItems The array of exported object details.
         * 
         * @return builder
         * 
         */
        public Builder exportedItems(@Nullable Output<List<WorkspaceExportRequestExportedItemArgs>> exportedItems) {
            $.exportedItems = exportedItems;
            return this;
        }

        /**
         * @param exportedItems The array of exported object details.
         * 
         * @return builder
         * 
         */
        public Builder exportedItems(List<WorkspaceExportRequestExportedItemArgs> exportedItems) {
            return exportedItems(Output.of(exportedItems));
        }

        /**
         * @param exportedItems The array of exported object details.
         * 
         * @return builder
         * 
         */
        public Builder exportedItems(WorkspaceExportRequestExportedItemArgs... exportedItems) {
            return exportedItems(List.of(exportedItems));
        }

        /**
         * @param fileName Name of the exported zip file.
         * 
         * @return builder
         * 
         */
        public Builder fileName(@Nullable Output<String> fileName) {
            $.fileName = fileName;
            return this;
        }

        /**
         * @param fileName Name of the exported zip file.
         * 
         * @return builder
         * 
         */
        public Builder fileName(String fileName) {
            return fileName(Output.of(fileName));
        }

        /**
         * @param filters Filters for exported objects
         * 
         * @return builder
         * 
         */
        public Builder filters(@Nullable Output<List<String>> filters) {
            $.filters = filters;
            return this;
        }

        /**
         * @param filters Filters for exported objects
         * 
         * @return builder
         * 
         */
        public Builder filters(List<String> filters) {
            return filters(Output.of(filters));
        }

        /**
         * @param filters Filters for exported objects
         * 
         * @return builder
         * 
         */
        public Builder filters(String... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isObjectOverwriteEnabled Flag to control whether to overwrite the object if it is already present at the provided object storage location.
         * 
         * @return builder
         * 
         */
        public Builder isObjectOverwriteEnabled(@Nullable Output<Boolean> isObjectOverwriteEnabled) {
            $.isObjectOverwriteEnabled = isObjectOverwriteEnabled;
            return this;
        }

        /**
         * @param isObjectOverwriteEnabled Flag to control whether to overwrite the object if it is already present at the provided object storage location.
         * 
         * @return builder
         * 
         */
        public Builder isObjectOverwriteEnabled(Boolean isObjectOverwriteEnabled) {
            return isObjectOverwriteEnabled(Output.of(isObjectOverwriteEnabled));
        }

        /**
         * @param key Export object request key
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key Export object request key
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param name Name of the export request.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name of the export request.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param objectKeys Field is used to specify which object keys to export
         * 
         * @return builder
         * 
         */
        public Builder objectKeys(@Nullable Output<List<String>> objectKeys) {
            $.objectKeys = objectKeys;
            return this;
        }

        /**
         * @param objectKeys Field is used to specify which object keys to export
         * 
         * @return builder
         * 
         */
        public Builder objectKeys(List<String> objectKeys) {
            return objectKeys(Output.of(objectKeys));
        }

        /**
         * @param objectKeys Field is used to specify which object keys to export
         * 
         * @return builder
         * 
         */
        public Builder objectKeys(String... objectKeys) {
            return objectKeys(List.of(objectKeys));
        }

        /**
         * @param objectStorageRegion Region of the object storage (if using object storage of different region)
         * 
         * @return builder
         * 
         */
        public Builder objectStorageRegion(@Nullable Output<String> objectStorageRegion) {
            $.objectStorageRegion = objectStorageRegion;
            return this;
        }

        /**
         * @param objectStorageRegion Region of the object storage (if using object storage of different region)
         * 
         * @return builder
         * 
         */
        public Builder objectStorageRegion(String objectStorageRegion) {
            return objectStorageRegion(Output.of(objectStorageRegion));
        }

        /**
         * @param objectStorageTenancyId Optional parameter to point to object storage tenancy (if using Object Storage of different tenancy)
         * 
         * @return builder
         * 
         */
        public Builder objectStorageTenancyId(@Nullable Output<String> objectStorageTenancyId) {
            $.objectStorageTenancyId = objectStorageTenancyId;
            return this;
        }

        /**
         * @param objectStorageTenancyId Optional parameter to point to object storage tenancy (if using Object Storage of different tenancy)
         * 
         * @return builder
         * 
         */
        public Builder objectStorageTenancyId(String objectStorageTenancyId) {
            return objectStorageTenancyId(Output.of(objectStorageTenancyId));
        }

        /**
         * @param referencedItems The array of exported referenced objects.
         * 
         * @return builder
         * 
         */
        public Builder referencedItems(@Nullable Output<String> referencedItems) {
            $.referencedItems = referencedItems;
            return this;
        }

        /**
         * @param referencedItems The array of exported referenced objects.
         * 
         * @return builder
         * 
         */
        public Builder referencedItems(String referencedItems) {
            return referencedItems(Output.of(referencedItems));
        }

        /**
         * @param status Export Objects request status.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status Export Objects request status.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param timeEndedInMillis Time at which the request was completely processed.
         * 
         * @return builder
         * 
         */
        public Builder timeEndedInMillis(@Nullable Output<String> timeEndedInMillis) {
            $.timeEndedInMillis = timeEndedInMillis;
            return this;
        }

        /**
         * @param timeEndedInMillis Time at which the request was completely processed.
         * 
         * @return builder
         * 
         */
        public Builder timeEndedInMillis(String timeEndedInMillis) {
            return timeEndedInMillis(Output.of(timeEndedInMillis));
        }

        /**
         * @param timeStartedInMillis Time at which the request started getting processed.
         * 
         * @return builder
         * 
         */
        public Builder timeStartedInMillis(@Nullable Output<String> timeStartedInMillis) {
            $.timeStartedInMillis = timeStartedInMillis;
            return this;
        }

        /**
         * @param timeStartedInMillis Time at which the request started getting processed.
         * 
         * @return builder
         * 
         */
        public Builder timeStartedInMillis(String timeStartedInMillis) {
            return timeStartedInMillis(Output.of(timeStartedInMillis));
        }

        /**
         * @param totalExportedObjectCount Number of objects that are exported.
         * 
         * @return builder
         * 
         */
        public Builder totalExportedObjectCount(@Nullable Output<Integer> totalExportedObjectCount) {
            $.totalExportedObjectCount = totalExportedObjectCount;
            return this;
        }

        /**
         * @param totalExportedObjectCount Number of objects that are exported.
         * 
         * @return builder
         * 
         */
        public Builder totalExportedObjectCount(Integer totalExportedObjectCount) {
            return totalExportedObjectCount(Output.of(totalExportedObjectCount));
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

        public WorkspaceExportRequestState build() {
            return $;
        }
    }

}