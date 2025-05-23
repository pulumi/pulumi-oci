// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetLustreFileStorageLustreFileSystemArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLustreFileStorageLustreFileSystemArgs Empty = new GetLustreFileStorageLustreFileSystemArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Lustre file system.
     * 
     */
    @Import(name="lustreFileSystemId", required=true)
    private Output<String> lustreFileSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Lustre file system.
     * 
     */
    public Output<String> lustreFileSystemId() {
        return this.lustreFileSystemId;
    }

    private GetLustreFileStorageLustreFileSystemArgs() {}

    private GetLustreFileStorageLustreFileSystemArgs(GetLustreFileStorageLustreFileSystemArgs $) {
        this.lustreFileSystemId = $.lustreFileSystemId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLustreFileStorageLustreFileSystemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLustreFileStorageLustreFileSystemArgs $;

        public Builder() {
            $ = new GetLustreFileStorageLustreFileSystemArgs();
        }

        public Builder(GetLustreFileStorageLustreFileSystemArgs defaults) {
            $ = new GetLustreFileStorageLustreFileSystemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param lustreFileSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Lustre file system.
         * 
         * @return builder
         * 
         */
        public Builder lustreFileSystemId(Output<String> lustreFileSystemId) {
            $.lustreFileSystemId = lustreFileSystemId;
            return this;
        }

        /**
         * @param lustreFileSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Lustre file system.
         * 
         * @return builder
         * 
         */
        public Builder lustreFileSystemId(String lustreFileSystemId) {
            return lustreFileSystemId(Output.of(lustreFileSystemId));
        }

        public GetLustreFileStorageLustreFileSystemArgs build() {
            if ($.lustreFileSystemId == null) {
                throw new MissingRequiredPropertyException("GetLustreFileStorageLustreFileSystemArgs", "lustreFileSystemId");
            }
            return $;
        }
    }

}
