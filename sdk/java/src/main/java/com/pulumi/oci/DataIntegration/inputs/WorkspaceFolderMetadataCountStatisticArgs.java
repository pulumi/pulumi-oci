// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceFolderMetadataCountStatisticObjectTypeCountListArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceFolderMetadataCountStatisticArgs extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceFolderMetadataCountStatisticArgs Empty = new WorkspaceFolderMetadataCountStatisticArgs();

    /**
     * The array of statistics.
     * 
     */
    @Import(name="objectTypeCountLists")
    private @Nullable Output<List<WorkspaceFolderMetadataCountStatisticObjectTypeCountListArgs>> objectTypeCountLists;

    /**
     * @return The array of statistics.
     * 
     */
    public Optional<Output<List<WorkspaceFolderMetadataCountStatisticObjectTypeCountListArgs>>> objectTypeCountLists() {
        return Optional.ofNullable(this.objectTypeCountLists);
    }

    private WorkspaceFolderMetadataCountStatisticArgs() {}

    private WorkspaceFolderMetadataCountStatisticArgs(WorkspaceFolderMetadataCountStatisticArgs $) {
        this.objectTypeCountLists = $.objectTypeCountLists;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceFolderMetadataCountStatisticArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceFolderMetadataCountStatisticArgs $;

        public Builder() {
            $ = new WorkspaceFolderMetadataCountStatisticArgs();
        }

        public Builder(WorkspaceFolderMetadataCountStatisticArgs defaults) {
            $ = new WorkspaceFolderMetadataCountStatisticArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param objectTypeCountLists The array of statistics.
         * 
         * @return builder
         * 
         */
        public Builder objectTypeCountLists(@Nullable Output<List<WorkspaceFolderMetadataCountStatisticObjectTypeCountListArgs>> objectTypeCountLists) {
            $.objectTypeCountLists = objectTypeCountLists;
            return this;
        }

        /**
         * @param objectTypeCountLists The array of statistics.
         * 
         * @return builder
         * 
         */
        public Builder objectTypeCountLists(List<WorkspaceFolderMetadataCountStatisticObjectTypeCountListArgs> objectTypeCountLists) {
            return objectTypeCountLists(Output.of(objectTypeCountLists));
        }

        /**
         * @param objectTypeCountLists The array of statistics.
         * 
         * @return builder
         * 
         */
        public Builder objectTypeCountLists(WorkspaceFolderMetadataCountStatisticObjectTypeCountListArgs... objectTypeCountLists) {
            return objectTypeCountLists(List.of(objectTypeCountLists));
        }

        public WorkspaceFolderMetadataCountStatisticArgs build() {
            return $;
        }
    }

}