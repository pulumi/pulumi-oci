// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSnapshotPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSnapshotPlainArgs Empty = new GetSnapshotPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
     * 
     */
    @Import(name="snapshotId", required=true)
    private String snapshotId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
     * 
     */
    public String snapshotId() {
        return this.snapshotId;
    }

    private GetSnapshotPlainArgs() {}

    private GetSnapshotPlainArgs(GetSnapshotPlainArgs $) {
        this.snapshotId = $.snapshotId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSnapshotPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSnapshotPlainArgs $;

        public Builder() {
            $ = new GetSnapshotPlainArgs();
        }

        public Builder(GetSnapshotPlainArgs defaults) {
            $ = new GetSnapshotPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param snapshotId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
         * 
         * @return builder
         * 
         */
        public Builder snapshotId(String snapshotId) {
            $.snapshotId = snapshotId;
            return this;
        }

        public GetSnapshotPlainArgs build() {
            if ($.snapshotId == null) {
                throw new MissingRequiredPropertyException("GetSnapshotPlainArgs", "snapshotId");
            }
            return $;
        }
    }

}
