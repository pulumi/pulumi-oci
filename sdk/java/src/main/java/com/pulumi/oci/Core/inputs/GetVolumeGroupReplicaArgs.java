// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetVolumeGroupReplicaArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVolumeGroupReplicaArgs Empty = new GetVolumeGroupReplicaArgs();

    /**
     * The OCID of the volume replica group.
     * 
     */
    @Import(name="volumeGroupReplicaId", required=true)
    private Output<String> volumeGroupReplicaId;

    /**
     * @return The OCID of the volume replica group.
     * 
     */
    public Output<String> volumeGroupReplicaId() {
        return this.volumeGroupReplicaId;
    }

    private GetVolumeGroupReplicaArgs() {}

    private GetVolumeGroupReplicaArgs(GetVolumeGroupReplicaArgs $) {
        this.volumeGroupReplicaId = $.volumeGroupReplicaId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVolumeGroupReplicaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVolumeGroupReplicaArgs $;

        public Builder() {
            $ = new GetVolumeGroupReplicaArgs();
        }

        public Builder(GetVolumeGroupReplicaArgs defaults) {
            $ = new GetVolumeGroupReplicaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param volumeGroupReplicaId The OCID of the volume replica group.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupReplicaId(Output<String> volumeGroupReplicaId) {
            $.volumeGroupReplicaId = volumeGroupReplicaId;
            return this;
        }

        /**
         * @param volumeGroupReplicaId The OCID of the volume replica group.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupReplicaId(String volumeGroupReplicaId) {
            return volumeGroupReplicaId(Output.of(volumeGroupReplicaId));
        }

        public GetVolumeGroupReplicaArgs build() {
            $.volumeGroupReplicaId = Objects.requireNonNull($.volumeGroupReplicaId, "expected parameter 'volumeGroupReplicaId' to be non-null");
            return $;
        }
    }

}