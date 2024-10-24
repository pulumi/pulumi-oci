// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDbManagementPrivateEndpointAssociatedDatabaseArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbManagementPrivateEndpointAssociatedDatabaseArgs Empty = new GetDbManagementPrivateEndpointAssociatedDatabaseArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
     * 
     */
    @Import(name="dbManagementPrivateEndpointId", required=true)
    private Output<String> dbManagementPrivateEndpointId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
     * 
     */
    public Output<String> dbManagementPrivateEndpointId() {
        return this.dbManagementPrivateEndpointId;
    }

    private GetDbManagementPrivateEndpointAssociatedDatabaseArgs() {}

    private GetDbManagementPrivateEndpointAssociatedDatabaseArgs(GetDbManagementPrivateEndpointAssociatedDatabaseArgs $) {
        this.compartmentId = $.compartmentId;
        this.dbManagementPrivateEndpointId = $.dbManagementPrivateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbManagementPrivateEndpointAssociatedDatabaseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbManagementPrivateEndpointAssociatedDatabaseArgs $;

        public Builder() {
            $ = new GetDbManagementPrivateEndpointAssociatedDatabaseArgs();
        }

        public Builder(GetDbManagementPrivateEndpointAssociatedDatabaseArgs defaults) {
            $ = new GetDbManagementPrivateEndpointAssociatedDatabaseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dbManagementPrivateEndpointId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder dbManagementPrivateEndpointId(Output<String> dbManagementPrivateEndpointId) {
            $.dbManagementPrivateEndpointId = dbManagementPrivateEndpointId;
            return this;
        }

        /**
         * @param dbManagementPrivateEndpointId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder dbManagementPrivateEndpointId(String dbManagementPrivateEndpointId) {
            return dbManagementPrivateEndpointId(Output.of(dbManagementPrivateEndpointId));
        }

        public GetDbManagementPrivateEndpointAssociatedDatabaseArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDbManagementPrivateEndpointAssociatedDatabaseArgs", "compartmentId");
            }
            if ($.dbManagementPrivateEndpointId == null) {
                throw new MissingRequiredPropertyException("GetDbManagementPrivateEndpointAssociatedDatabaseArgs", "dbManagementPrivateEndpointId");
            }
            return $;
        }
    }

}
