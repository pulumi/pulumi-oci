// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetHeatWaveClusterArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetHeatWaveClusterArgs Empty = new GetHeatWaveClusterArgs();

    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbSystemId", required=true)
    private Output<String> dbSystemId;

    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbSystemId() {
        return this.dbSystemId;
    }

    private GetHeatWaveClusterArgs() {}

    private GetHeatWaveClusterArgs(GetHeatWaveClusterArgs $) {
        this.dbSystemId = $.dbSystemId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetHeatWaveClusterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetHeatWaveClusterArgs $;

        public Builder() {
            $ = new GetHeatWaveClusterArgs();
        }

        public Builder(GetHeatWaveClusterArgs defaults) {
            $ = new GetHeatWaveClusterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(Output<String> dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            return dbSystemId(Output.of(dbSystemId));
        }

        public GetHeatWaveClusterArgs build() {
            if ($.dbSystemId == null) {
                throw new MissingRequiredPropertyException("GetHeatWaveClusterArgs", "dbSystemId");
            }
            return $;
        }
    }

}
