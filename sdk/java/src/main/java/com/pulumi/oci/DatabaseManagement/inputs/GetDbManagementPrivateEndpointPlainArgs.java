// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetDbManagementPrivateEndpointPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbManagementPrivateEndpointPlainArgs Empty = new GetDbManagementPrivateEndpointPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
     * 
     */
    @Import(name="dbManagementPrivateEndpointId", required=true)
    private String dbManagementPrivateEndpointId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
     * 
     */
    public String dbManagementPrivateEndpointId() {
        return this.dbManagementPrivateEndpointId;
    }

    private GetDbManagementPrivateEndpointPlainArgs() {}

    private GetDbManagementPrivateEndpointPlainArgs(GetDbManagementPrivateEndpointPlainArgs $) {
        this.dbManagementPrivateEndpointId = $.dbManagementPrivateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbManagementPrivateEndpointPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbManagementPrivateEndpointPlainArgs $;

        public Builder() {
            $ = new GetDbManagementPrivateEndpointPlainArgs();
        }

        public Builder(GetDbManagementPrivateEndpointPlainArgs defaults) {
            $ = new GetDbManagementPrivateEndpointPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbManagementPrivateEndpointId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder dbManagementPrivateEndpointId(String dbManagementPrivateEndpointId) {
            $.dbManagementPrivateEndpointId = dbManagementPrivateEndpointId;
            return this;
        }

        public GetDbManagementPrivateEndpointPlainArgs build() {
            $.dbManagementPrivateEndpointId = Objects.requireNonNull($.dbManagementPrivateEndpointId, "expected parameter 'dbManagementPrivateEndpointId' to be non-null");
            return $;
        }
    }

}