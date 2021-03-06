// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetailsArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NotebookSessionNotebookSessionConfigurationDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final NotebookSessionNotebookSessionConfigurationDetailsArgs Empty = new NotebookSessionNotebookSessionConfigurationDetailsArgs();

    /**
     * (Updatable) A notebook session instance is provided with a block storage volume. This specifies the size of the volume in GBs.
     * 
     */
    @Import(name="blockStorageSizeInGbs")
    private @Nullable Output<Integer> blockStorageSizeInGbs;

    /**
     * @return (Updatable) A notebook session instance is provided with a block storage volume. This specifies the size of the volume in GBs.
     * 
     */
    public Optional<Output<Integer>> blockStorageSizeInGbs() {
        return Optional.ofNullable(this.blockStorageSizeInGbs);
    }

    /**
     * (Updatable) Details for the notebook session shape configuration.
     * 
     */
    @Import(name="notebookSessionShapeConfigDetails")
    private @Nullable Output<NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetailsArgs> notebookSessionShapeConfigDetails;

    /**
     * @return (Updatable) Details for the notebook session shape configuration.
     * 
     */
    public Optional<Output<NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetailsArgs>> notebookSessionShapeConfigDetails() {
        return Optional.ofNullable(this.notebookSessionShapeConfigDetails);
    }

    /**
     * (Updatable) The shape used to launch the notebook session compute instance.  The list of available shapes in a given compartment can be retrieved using the `ListNotebookSessionShapes` endpoint.
     * 
     */
    @Import(name="shape", required=true)
    private Output<String> shape;

    /**
     * @return (Updatable) The shape used to launch the notebook session compute instance.  The list of available shapes in a given compartment can be retrieved using the `ListNotebookSessionShapes` endpoint.
     * 
     */
    public Output<String> shape() {
        return this.shape;
    }

    /**
     * (Updatable) A notebook session instance is provided with a VNIC for network access.  This specifies the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet to create a VNIC in.  The subnet should be in a VCN with a NAT gateway for egress to the internet.
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return (Updatable) A notebook session instance is provided with a VNIC for network access.  This specifies the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet to create a VNIC in.  The subnet should be in a VCN with a NAT gateway for egress to the internet.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    private NotebookSessionNotebookSessionConfigurationDetailsArgs() {}

    private NotebookSessionNotebookSessionConfigurationDetailsArgs(NotebookSessionNotebookSessionConfigurationDetailsArgs $) {
        this.blockStorageSizeInGbs = $.blockStorageSizeInGbs;
        this.notebookSessionShapeConfigDetails = $.notebookSessionShapeConfigDetails;
        this.shape = $.shape;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NotebookSessionNotebookSessionConfigurationDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NotebookSessionNotebookSessionConfigurationDetailsArgs $;

        public Builder() {
            $ = new NotebookSessionNotebookSessionConfigurationDetailsArgs();
        }

        public Builder(NotebookSessionNotebookSessionConfigurationDetailsArgs defaults) {
            $ = new NotebookSessionNotebookSessionConfigurationDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param blockStorageSizeInGbs (Updatable) A notebook session instance is provided with a block storage volume. This specifies the size of the volume in GBs.
         * 
         * @return builder
         * 
         */
        public Builder blockStorageSizeInGbs(@Nullable Output<Integer> blockStorageSizeInGbs) {
            $.blockStorageSizeInGbs = blockStorageSizeInGbs;
            return this;
        }

        /**
         * @param blockStorageSizeInGbs (Updatable) A notebook session instance is provided with a block storage volume. This specifies the size of the volume in GBs.
         * 
         * @return builder
         * 
         */
        public Builder blockStorageSizeInGbs(Integer blockStorageSizeInGbs) {
            return blockStorageSizeInGbs(Output.of(blockStorageSizeInGbs));
        }

        /**
         * @param notebookSessionShapeConfigDetails (Updatable) Details for the notebook session shape configuration.
         * 
         * @return builder
         * 
         */
        public Builder notebookSessionShapeConfigDetails(@Nullable Output<NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetailsArgs> notebookSessionShapeConfigDetails) {
            $.notebookSessionShapeConfigDetails = notebookSessionShapeConfigDetails;
            return this;
        }

        /**
         * @param notebookSessionShapeConfigDetails (Updatable) Details for the notebook session shape configuration.
         * 
         * @return builder
         * 
         */
        public Builder notebookSessionShapeConfigDetails(NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetailsArgs notebookSessionShapeConfigDetails) {
            return notebookSessionShapeConfigDetails(Output.of(notebookSessionShapeConfigDetails));
        }

        /**
         * @param shape (Updatable) The shape used to launch the notebook session compute instance.  The list of available shapes in a given compartment can be retrieved using the `ListNotebookSessionShapes` endpoint.
         * 
         * @return builder
         * 
         */
        public Builder shape(Output<String> shape) {
            $.shape = shape;
            return this;
        }

        /**
         * @param shape (Updatable) The shape used to launch the notebook session compute instance.  The list of available shapes in a given compartment can be retrieved using the `ListNotebookSessionShapes` endpoint.
         * 
         * @return builder
         * 
         */
        public Builder shape(String shape) {
            return shape(Output.of(shape));
        }

        /**
         * @param subnetId (Updatable) A notebook session instance is provided with a VNIC for network access.  This specifies the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet to create a VNIC in.  The subnet should be in a VCN with a NAT gateway for egress to the internet.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId (Updatable) A notebook session instance is provided with a VNIC for network access.  This specifies the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet to create a VNIC in.  The subnet should be in a VCN with a NAT gateway for egress to the internet.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public NotebookSessionNotebookSessionConfigurationDetailsArgs build() {
            $.shape = Objects.requireNonNull($.shape, "expected parameter 'shape' to be non-null");
            $.subnetId = Objects.requireNonNull($.subnetId, "expected parameter 'subnetId' to be non-null");
            return $;
        }
    }

}
