// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetExadataIormConfigArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExadataIormConfigArgs Empty = new GetExadataIormConfigArgs();

    /**
     * The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbSystemId", required=true)
    private Output<String> dbSystemId;

    /**
     * @return The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbSystemId() {
        return this.dbSystemId;
    }

    private GetExadataIormConfigArgs() {}

    private GetExadataIormConfigArgs(GetExadataIormConfigArgs $) {
        this.dbSystemId = $.dbSystemId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExadataIormConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExadataIormConfigArgs $;

        public Builder() {
            $ = new GetExadataIormConfigArgs();
        }

        public Builder(GetExadataIormConfigArgs defaults) {
            $ = new GetExadataIormConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbSystemId The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(Output<String> dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param dbSystemId The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            return dbSystemId(Output.of(dbSystemId));
        }

        public GetExadataIormConfigArgs build() {
            $.dbSystemId = Objects.requireNonNull($.dbSystemId, "expected parameter 'dbSystemId' to be non-null");
            return $;
        }
    }

}