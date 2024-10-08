// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataIntegration.inputs.WorkspaceApplicationMetadataCountStatisticObjectTypeCountListArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceApplicationMetadataCountStatisticArgs extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceApplicationMetadataCountStatisticArgs Empty = new WorkspaceApplicationMetadataCountStatisticArgs();

    /**
     * The array of statistics.
     * 
     */
    @Import(name="objectTypeCountLists")
    private @Nullable Output<List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountListArgs>> objectTypeCountLists;

    /**
     * @return The array of statistics.
     * 
     */
    public Optional<Output<List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountListArgs>>> objectTypeCountLists() {
        return Optional.ofNullable(this.objectTypeCountLists);
    }

    private WorkspaceApplicationMetadataCountStatisticArgs() {}

    private WorkspaceApplicationMetadataCountStatisticArgs(WorkspaceApplicationMetadataCountStatisticArgs $) {
        this.objectTypeCountLists = $.objectTypeCountLists;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceApplicationMetadataCountStatisticArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceApplicationMetadataCountStatisticArgs $;

        public Builder() {
            $ = new WorkspaceApplicationMetadataCountStatisticArgs();
        }

        public Builder(WorkspaceApplicationMetadataCountStatisticArgs defaults) {
            $ = new WorkspaceApplicationMetadataCountStatisticArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param objectTypeCountLists The array of statistics.
         * 
         * @return builder
         * 
         */
        public Builder objectTypeCountLists(@Nullable Output<List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountListArgs>> objectTypeCountLists) {
            $.objectTypeCountLists = objectTypeCountLists;
            return this;
        }

        /**
         * @param objectTypeCountLists The array of statistics.
         * 
         * @return builder
         * 
         */
        public Builder objectTypeCountLists(List<WorkspaceApplicationMetadataCountStatisticObjectTypeCountListArgs> objectTypeCountLists) {
            return objectTypeCountLists(Output.of(objectTypeCountLists));
        }

        /**
         * @param objectTypeCountLists The array of statistics.
         * 
         * @return builder
         * 
         */
        public Builder objectTypeCountLists(WorkspaceApplicationMetadataCountStatisticObjectTypeCountListArgs... objectTypeCountLists) {
            return objectTypeCountLists(List.of(objectTypeCountLists));
        }

        public WorkspaceApplicationMetadataCountStatisticArgs build() {
            return $;
        }
    }

}
