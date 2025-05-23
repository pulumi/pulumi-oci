// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetExternalExadataStorageServerIormPlanPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalExadataStorageServerIormPlanPlainArgs Empty = new GetExternalExadataStorageServerIormPlanPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
     * 
     */
    @Import(name="externalExadataStorageServerId", required=true)
    private String externalExadataStorageServerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
     * 
     */
    public String externalExadataStorageServerId() {
        return this.externalExadataStorageServerId;
    }

    private GetExternalExadataStorageServerIormPlanPlainArgs() {}

    private GetExternalExadataStorageServerIormPlanPlainArgs(GetExternalExadataStorageServerIormPlanPlainArgs $) {
        this.externalExadataStorageServerId = $.externalExadataStorageServerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalExadataStorageServerIormPlanPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalExadataStorageServerIormPlanPlainArgs $;

        public Builder() {
            $ = new GetExternalExadataStorageServerIormPlanPlainArgs();
        }

        public Builder(GetExternalExadataStorageServerIormPlanPlainArgs defaults) {
            $ = new GetExternalExadataStorageServerIormPlanPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param externalExadataStorageServerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
         * 
         * @return builder
         * 
         */
        public Builder externalExadataStorageServerId(String externalExadataStorageServerId) {
            $.externalExadataStorageServerId = externalExadataStorageServerId;
            return this;
        }

        public GetExternalExadataStorageServerIormPlanPlainArgs build() {
            if ($.externalExadataStorageServerId == null) {
                throw new MissingRequiredPropertyException("GetExternalExadataStorageServerIormPlanPlainArgs", "externalExadataStorageServerId");
            }
            return $;
        }
    }

}
